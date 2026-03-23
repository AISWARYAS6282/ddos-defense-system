
import re
from flask import jsonify, request, current_app
from flask_login import login_required, current_user
import requests as http_requests
from . import api_bp
from ...extensions import db, socketio
from ...models.blocked_ip import BlockedIP
from ...models.response_log import ResponseLog
from ...models.simulator_config import SimulatorConfig
from ...models.attack import Attack
from datetime import datetime

_IP_RE = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')

def _valid_ip(ip):
    if not ip or not _IP_RE.match(ip): return False
    return all(0 <= int(p) <= 255 for p in ip.split('.'))

def _call_sandbox(action, ip):
    agent_url = current_app.config['SANDBOX_AGENT_URL']
    token     = current_app.config['SANDBOX_AGENT_TOKEN']
    try:
        resp = http_requests.post(f'{agent_url}/apply_block',
            json={'ip': ip, 'action': action},
            headers={'Authorization': f'Bearer {token}'}, timeout=5)
        return resp.json()
    except Exception as e:
        return {'status': 'error', 'message': str(e)}

@api_bp.route('/status')
def status():
    from ...simulator_manager import simulator_manager
    return jsonify({'status': 'ok', 'division': 2,
                    'simulator_running': simulator_manager.running})

@api_bp.route('/simulator/start', methods=['POST'])
@login_required
def sim_start():
    from ...simulator_manager import simulator_manager
    started = simulator_manager.start(socketio, current_app._get_current_object())
    if not started: return jsonify({'running': True, 'message': 'Already running'})
    socketio.emit('sim_status', {'running': True, 'started_by': current_user.username})
    return jsonify({'running': True, 'message': 'Simulator started'})

@api_bp.route('/simulator/stop', methods=['POST'])
@login_required
def sim_stop():
    from ...simulator_manager import simulator_manager
    simulator_manager.stop()
    socketio.emit('sim_status', {'running': False, 'stopped_by': current_user.username})
    return jsonify({'running': False, 'message': 'Simulator stopped'})

@api_bp.route('/simulator/status')
@login_required
def sim_status():
    from ...simulator_manager import simulator_manager
    cfg = SimulatorConfig.query.first()
    return jsonify({'running': simulator_manager.running,
                    'attack_rate': cfg.attack_rate if cfg else 1.0,
                    'attack_ratio': cfg.attack_ratio if cfg else 0.3})

@api_bp.route('/block', methods=['POST'])
@login_required
def block_ip():
    data = request.get_json() or {}
    ip   = data.get('ip', '').strip()
    reason = data.get('reason', 'Manual block')
    if not _valid_ip(ip): return jsonify({'error': 'Invalid IP address'}), 400
    existing = BlockedIP.query.filter_by(ip_address=ip).first()
    if existing and existing.is_active:
        return jsonify({'error': 'IP already blocked'}), 409
    sandbox_resp = _call_sandbox('BLOCK', ip)
    if existing:
        existing.is_active = True; existing.reason = reason
        existing.blocked_by = current_user.username
        existing.blocked_at = datetime.utcnow()
    else:
        db.session.add(BlockedIP(ip_address=ip, reason=reason,
                                 blocked_by=current_user.username))
    Attack.query.filter_by(source_ip=ip, status='active').update({'status': 'blocked'})
    db.session.add(ResponseLog(action='BLOCK', target_ip=ip,
        performed_by=current_user.username,
        status=sandbox_resp.get('status', 'unknown'),
        message=sandbox_resp.get('message', ''),
        sandbox_response=sandbox_resp))
    db.session.commit()
    socketio.emit('ip_blocked', {'ip': ip, 'reason': reason,
        'blocked_by': current_user.username,
        'timestamp': datetime.utcnow().isoformat()})
    return jsonify({'success': True, 'ip': ip, 'sandbox': sandbox_resp})

@api_bp.route('/unblock', methods=['POST'])
@login_required
def unblock_ip():
    data = request.get_json() or {}
    ip   = data.get('ip', '').strip()
    if not _valid_ip(ip): return jsonify({'error': 'Invalid IP'}), 400
    block = BlockedIP.query.filter_by(ip_address=ip, is_active=True).first()
    if not block: return jsonify({'error': 'IP not currently blocked'}), 404
    sandbox_resp = _call_sandbox('UNBLOCK', ip)
    block.is_active = False
    db.session.add(ResponseLog(action='UNBLOCK', target_ip=ip,
        performed_by=current_user.username,
        status=sandbox_resp.get('status', 'unknown'),
        message=sandbox_resp.get('message', ''),
        sandbox_response=sandbox_resp))
    db.session.commit()
    socketio.emit('ip_unblocked', {'ip': ip,
        'unblocked_by': current_user.username,
        'timestamp': datetime.utcnow().isoformat()})
    return jsonify({'success': True, 'ip': ip})

@api_bp.route('/ignore', methods=['POST'])
@login_required
def ignore_alert():
    data = request.get_json() or {}
    attack_id = data.get('attack_id')
    if not attack_id: return jsonify({'error': 'attack_id required'}), 400
    attack = Attack.query.get(attack_id)
    if not attack: return jsonify({'error': 'Not found'}), 404
    if attack.status != 'active':
        return jsonify({'error': f'Already {attack.status}'}), 409
    attack.status = 'ignored'; attack.resolved = True
    db.session.commit()
    socketio.emit('alert_ignored', {'attack_id': attack_id,
        'ip': attack.source_ip, 'ignored_by': current_user.username})
    return jsonify({'success': True, 'attack_id': attack_id})

@api_bp.route('/stats')
@login_required
def stats():
    from ...simulator_manager import simulator_manager
    return jsonify({
        'total_attacks':    Attack.query.count(),
        'active_alerts':    Attack.query.filter_by(status='active').count(),
        'blocked_alerts':   Attack.query.filter_by(status='blocked').count(),
        'ignored_alerts':   Attack.query.filter_by(status='ignored').count(),
        'blocked_ips':      BlockedIP.query.filter_by(is_active=True).count(),
        'simulator_running': simulator_manager.running,
    })

@api_bp.route('/blocked-ips')
@login_required
def list_blocked():
    ips = BlockedIP.query.filter_by(is_active=True).all()
    return jsonify([{'id': b.id, 'ip': b.ip_address, 'reason': b.reason,
        'blocked_by': b.blocked_by, 'blocked_at': b.blocked_at.isoformat()}
        for b in ips])

@api_bp.route('/attacks')
@login_required
def list_attacks():
    limit  = min(int(request.args.get('limit', 100)), 500)
    status = request.args.get('status')
    q = Attack.query.order_by(Attack.detected_at.desc())
    if status: q = q.filter_by(status=status)
    return jsonify([a.to_dict() for a in q.limit(limit).all()])
