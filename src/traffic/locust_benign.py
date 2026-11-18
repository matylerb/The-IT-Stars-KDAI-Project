"""
Benign traffic generator.

Simulates normal shoppers browsing Juice Shop: searching, viewing products,
registering accounts. Each simulated user gets its own fake X-Forwarded-For
IP, so the dataset has realistic per-user variety instead of every benign
request sharing one IP.

Usage:
    locust -f src/traffic/locust_benign.py --host http://localhost:8080
Then open http://localhost:8089 and set the number of users and spawn rate,
or run headless:
    locust -f src/traffic/locust_benign.py --host http://localhost:8080 \
        --headless -u 10 -r 2 -t 3m
"""
import random
import uuid

from locust import HttpUser, task, between

SEARCH_TERMS = ["apple", "juice", "banana", "lemon", "carrot", "mango",
                "smoothie", "water", "tea", "cordial"]


class BenignShopper(HttpUser):
    """One simulated normal visitor browsing the shop."""
    wait_time = between(1, 4)

    def on_start(self):
        # Give each simulated user its own fake IP, so the access log shows
        # distinct, realistic client IPs for benign traffic instead of all
        # sharing the Docker gateway address.
        octet = random.randint(2, 254)
        self.fake_ip = f"10.1.0.{octet}"
        self.client.headers.update({"X-Forwarded-For": self.fake_ip})

    @task(4)
    def search_products(self):
        term = random.choice(SEARCH_TERMS)
        self.client.get(f"/rest/products/search?q={term}", name="/rest/products/search")

    @task(3)
    def browse_product(self):
        product_id = random.randint(1, 40)
        self.client.get(f"/api/Products/{product_id}", name="/api/Products/[id]")

    @task(2)
    def view_homepage(self):
        self.client.get("/")

    @task(1)
    def register_account(self):
        email = f"user_{uuid.uuid4().hex[:8]}@test.com"
        self.client.post(
            "/api/Users",
            json={"email": email, "password": "Benign123!", "passwordRepeat": "Benign123!"},
            name="/api/Users (register)",
        )

    @task(1)
    def view_about(self):
        self.client.get("/", name="/ (about/static page)")