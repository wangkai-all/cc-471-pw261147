"""初始化演示数据：两个租户、管理员与业务用户、带敏感列的订单数据集及策略。"""
from __future__ import annotations

from app.database import Base, SessionLocal, engine
from app.models import Dataset, DatasetColumn, DatasetRow, Policy, Tenant, User


def seed() -> None:
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        t_acme = Tenant(name="acme")
        t_beta = Tenant(name="beta")
        db.add_all([t_acme, t_beta])
        db.flush()

        admin = User(username="admin", display_name="平台管理员", tenant_id=t_acme.id, is_admin=True)
        u_acme = User(username="alice", display_name="Alice (ACME)", tenant_id=t_acme.id)
        u_beta = User(username="bob", display_name="Bob (BETA)", tenant_id=t_beta.id)
        db.add_all([admin, u_acme, u_beta])
        db.flush()

        ds = Dataset(
            name="orders",
            description="跨租户订单数据（含手机号/薪资等敏感列）",
            owner_tenant_id=t_acme.id,
            export_policy="invalidate",
            auth_version=1,
        )
        db.add(ds)
        db.flush()
        for spec in [
            ("order_id", "string", False, "none"),
            ("amount", "number", False, "none"),
            ("region", "string", False, "none"),
            ("mobile", "string", True, "redact"),
            ("salary", "number", True, "hash"),
        ]:
            db.add(
                DatasetColumn(
                    dataset_id=ds.id, name=spec[0], data_type=spec[1],
                    sensitive=spec[2], default_mask=spec[3],
                )
            )

        rows = [
            (t_acme.id, {"order_id": "A-1001", "amount": 1200, "region": "north", "mobile": "13800000001", "salary": 9000}),
            (t_acme.id, {"order_id": "A-1002", "amount": 3400, "region": "south", "mobile": "13800000002", "salary": 12000}),
            (t_acme.id, {"order_id": "A-1003", "amount": 800,  "region": "north", "mobile": "13800000003", "salary": 7000}),
            (t_beta.id, {"order_id": "B-2001", "amount": 560,  "region": "north", "mobile": "13900000001", "salary": 6000}),
            (t_beta.id, {"order_id": "B-2002", "amount": 2900, "region": "west",  "mobile": "13900000002", "salary": 15000}),
        ]
        for tenant_id, data in rows:
            db.add(DatasetRow(dataset_id=ds.id, tenant_id=tenant_id, data=data))

        # 默认策略：两个租户用户都只能看本租户行；敏感列默认不可见（引擎按列定义脱敏）
        db.add(Policy(dataset_id=ds.id, subject_tenant_id=t_acme.id, effect="allow",
                      scope="row", row_scope="tenant", description="ACME 租户行级隔离"))
        db.add(Policy(dataset_id=ds.id, subject_tenant_id=t_beta.id, effect="allow",
                      scope="row", row_scope="tenant", description="BETA 租户行级隔离"))

        db.commit()
        print("seed done:")
        print(f"  tenants: acme={t_acme.id}, beta={t_beta.id}")
        print(f"  users: admin={admin.id}, alice(acme)={u_acme.id}, bob(beta)={u_beta.id}")
        print(f"  dataset: orders id={ds.id} (5 rows, sensitive cols: mobile/salary)")
    finally:
        db.close()


if __name__ == "__main__":
    seed()
