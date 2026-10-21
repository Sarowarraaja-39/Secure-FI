"""Optional durable AMQP notification bridge; SQL remains the authoritative job ledger.

Publish with broker confirms, then acknowledge wake-up notifications only after
SQL work completes. Notifications may duplicate; SQL pending/done state avoids
re-executing completed detection jobs. Run one bridge per sandbox tenant.
"""

import json
import os
import time
import pika
from securefi.platform.store import Store
from securefi.platform.product import Product as Platform
from securefi.platform.auth import initialise


def main():
    config, _ = initialise(os.environ.get("SECUREFI_AUTH_FILE", "data/access.json"))
    tenant = os.environ.get("SECUREFI_WORKER_TENANT", "fintech-lab")
    app = Platform(
        Store(os.environ.get("SECUREFI_DB", "data/platform.db")),
        config["pseudonym_key"],
    )
    actor = {"id": "queue-worker", "role": "ingestor", "tenant": tenant}
    connection = pika.BlockingConnection(
        pika.URLParameters(os.environ["SECUREFI_AMQP_URL"])
    )
    channel = connection.channel()
    queue = "securefi." + tenant
    channel.queue_declare(
        queue=queue, durable=True, arguments={"x-dead-letter-exchange": "securefi.dead"}
    )
    channel.exchange_declare(
        exchange="securefi.dead", exchange_type="fanout", durable=True
    )
    channel.queue_declare(queue=queue + ".dead", durable=True)
    channel.queue_bind(queue=queue + ".dead", exchange="securefi.dead")
    channel.confirm_delivery()
    channel.basic_qos(prefetch_count=1)
    while True:
        with app.store.connection() as conn:
            count = conn.execute(
                "SELECT COUNT(*) FROM jobs WHERE tenant=? AND state='pending'",
                (tenant,),
            ).fetchone()[0]
        if count:
            channel.basic_publish(
                exchange="",
                routing_key=queue,
                body=json.dumps({"tenant": tenant}),
                mandatory=True,
                properties=pika.BasicProperties(
                    delivery_mode=2, content_type="application/json"
                ),
            )
        method, properties, body = channel.basic_get(queue=queue, auto_ack=False)
        if method:
            try:
                if json.loads(body).get("tenant") != tenant:
                    raise ValueError("Tenant mismatch")
                app.work(actor, 100)
                channel.basic_ack(method.delivery_tag)
            except (ValueError, KeyError):
                channel.basic_nack(method.delivery_tag, requeue=False)
        connection.process_data_events(time_limit=0.2)
        time.sleep(0.3)


if __name__ == "__main__":
    main()
