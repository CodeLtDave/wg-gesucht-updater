#!/usr/bin/env python3

import argparse
import getpass
import time
import os

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
        self.get("https://www.wg-gesucht.de/")
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
        """Deactivate and immediately re-activate the offer."""
        api_url = f"https://www.wg-gesucht.de/api/offers/{ad_id}/users/{self.user_id}"
        headers = {
            "X-User-ID": self.user_id,
            "X-Client-ID": "wg_desktop_website",
            "X-Authorization": "Bearer " + self.cookies.get("X-Access-Token", ""),
            "X-Dev-Ref-No": self.cookies.get("X-Dev-Ref-No", "")
        }
        data = {"deactivated": "1", "csrf_token": self.csrf_token}
        self.patch(api_url, json=data, headers=headers)
        data["deactivated"] = "0"
        self.patch(api_url, json=data, headers=headers)
        print(f"Refreshed ad with nummer {ad_id}")


def read_secret(path: str, desc: str) -> str:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip()
    except Exception as e:
        raise RuntimeError(f"{desc} konnte nicht aus '{path}' gelesen werden: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Keep WG-Gesucht.de ads on top of the listing by regularly toggling their activation status.")
    parser.add_argument("--interval", type=int, default=3600,
                        help="How often to update the ads. Interval in seconds, default 3600 (1h).")
    parser.add_argument("--email-file", type=str, help="Path to a file containing the login email.")
    parser.add_argument("--password-file", type=str, help="Path to a file containing the password.")
    parser.add_argument("ad_id", nargs="+", help="The IDs of the ads.")
    args = parser.parse_args()

    if args.email_file:
        username = read_secret(args.email_file, "E-Mail")
    else:
        username = input("username: ")

    if args.password_file:
        password = read_secret(args.password_file, "Passwort")
    else:
        password = getpass.getpass("password: ")

    try:
        while True:
            session = WGGesuchtSession()
            session.login(username, password)
            for ad_id in args.ad_id:
                session.toggle_activation(ad_id)
            time.sleep(args.interval)

    except Exception as e:
        import traceback
        print("Fehler im Hauptloop:", e)
        traceback.print_exc()
        exit(1)

    print("Skript wurde beendet – das sollte nie passieren!")
    exit(1)
