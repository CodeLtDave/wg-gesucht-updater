#!/usr/bin/env python3

import argparse
import getpass
import time

import requests
from bs4 import BeautifulSoup


class WGGesuchtSession(requests.Session):
    def __init__(self):
        super().__init__()
        self.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:141.0) "
                "Gecko/20100101 Firefox/141.0"
            ),
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Requested-With": "XMLHttpRequest",
            "X-Client-Id": "wg_desktop_website",
            "X-Smp-Client": "WG-Gesucht",
            "Origin": "https://www.wg-gesucht.de",
            "Referer": "https://www.wg-gesucht.de/"
        })

    def login(self, email: str, password: str) -> bool:
            self.get("https://www.wg-gesucht.de/")  # Init session cookies
            url = "https://www.wg-gesucht.de/ajax/sessions.php?action=login"

            payload = {
                "login_email_username": email,
                "login_password": password,
                "login_form_auto_login": "1",
                "display_language": "de"
            }

            response = self.post(url, json=payload)
            if response.status_code != 200:
                raise RuntimeError(f"Login fehlgeschlagen mit Statuscode {response.status_code}")

            try:
                data = response.json()
            except ValueError:
                raise RuntimeError("Antwort ist kein JSON!")

            if "access_token" in data and "user_id" in data:
                self.access_token = data["access_token"]
                self.user_id = data["user_id"]
                self.csrf_token = data.get("csrf_token")
                return True
            else:
                raise RuntimeError("Login nicht erfolgreich – access_token fehlt.")

    def toggle_activation(self, ad_id):
        """ Deactivate and immediately re-activate the offer. """
        api_url = "https://www.wg-gesucht.de/api/offers/{}/users/{}".format(ad_id, self.user_id)
        headers = {"X-User-ID": self.user_id,
                   "X-Client-ID": "wg_desktop_website",
                   "X-Authorization": "Bearer " + self.cookies.get("X-Access-Token"),
                   "X-Dev-Ref-No": self.cookies.get("X-Dev-Ref-No")}
        data = {"deactivated": "1", "csrf_token": self.csrf_token}
        r = self.patch(api_url, json=data, headers=headers)
        data["deactivated"] = "0"
        r = self.patch(api_url, json=data, headers=headers)
        print(f"Refreshed ad with nummer {ad_id}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Keep WG-Gesucht.de ads on top of the listing by regularly toggling their activation status.')
    parser.add_argument("--interval", nargs=1, type=int, default=3600, help="How often to update the ads. Interval in seconds, default 3600 (1h).")
    parser.add_argument("ad_id", nargs="+", help="The IDs of the ads.")
    args = parser.parse_args()
    username = input("username:")
    password = getpass.getpass("password:")
    while True:
        session = WGGesuchtSession()
        session.login(username, password)
        for ad_id in args.ad_id:
            session.toggle_activation(ad_id)
        time.sleep(args.interval)
