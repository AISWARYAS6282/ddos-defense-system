#!/usr/bin/env python3
"""
Seed script — creates tables and bootstraps default users + simulator config.
Run once after migrations:
    flask db upgrade
    python seed.py
"""

import os
from app import create_app
from app.extensions import db
from app.models.user import User
from app.models.simulator_config import SimulatorConfig

app = create_app()


def seed():
    with app.app_context():
        db.create_all()
        print("✓ Tables ensured.")

        # Admin user
        if not User.query.filter_by(username="admin").first():
            admin = User(
                username="admin",
                email="admin@ddos-defense.local",
                role="admin",
            )
            admin.set_password(os.environ.get("ADMIN_PASSWORD", "Admin1234!"))
            db.session.add(admin)
            print("✓ Admin user created.")
        else:
            print("  Admin user already exists — skipped.")

        # Operator user
        if not User.query.filter_by(username="operator").first():
            operator = User(
                username="operator",
                email="operator@ddos-defense.local",
                role="operator",
            )
            operator.set_password(os.environ.get("OPERATOR_PASSWORD", "Operator1234!"))
            db.session.add(operator)
            print("✓ Operator user created.")
        else:
            print("  Operator user already exists — skipped.")

        # Default simulator config
        if not SimulatorConfig.query.first():
            cfg = SimulatorConfig(
                attack_rate=2.0,
                attack_ratio=0.3,
                attack_types=["SYN_FLOOD", "UDP_FLOOD", "HTTP_FLOOD", "ICMP_FLOOD", "DNS_AMPLIFICATION"],
                normal_ip_pool=[
                    "10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5",
                    "10.0.1.10", "10.0.1.11", "172.16.0.5",
                ],
                attacker_ip_pool=[
                    "192.168.100.10", "192.168.100.11", "192.168.100.12",
                    "203.0.113.5", "203.0.113.6",
                ],
                is_running=False,
                updated_by="seed",
            )
            db.session.add(cfg)
            print("✓ Simulator config created.")
        else:
            print("  Simulator config already exists — skipped.")

        db.session.commit()
        print("\n✅ Seed complete.")
        print("\nLogin credentials:")
        print("  admin    / Admin1234!    (role: admin)")
        print("  operator / Operator1234! (role: operator)")
        print("\nAccess: http://localhost:5000/auth/login")


if __name__ == "__main__":
    seed()
