import json
import os.path
import uuid

from flask import Flask
import requests

from py3xui import AsyncApi, Inbound, Client
import asyncio

from py3xui.inbound import Sniffing, StreamSettings, Settings

# vless://d2920599-c1a1-4d7c-8a3d-fb4110b7547c@77.238.252.197:443?type=tcp&security=none#server-inbound-server
# vless://d2920599-c1a1-4d7c-8a3d-fb4110b7547c@77.238.252.197:443?type=tcp&security=none#server-inbound-server

api_url = "3x-api:2053"
inbound_name = "server-inbound"
client_name = "server"
secret_path = "./data/secret.json"


async def init():
    api = AsyncApi(f"http://{api_url}", "admin", "admin")
    await api.login()

    settings = Settings(decryption="none")
    sniffing = Sniffing(enabled=True, destOverride=["tls", "http", "quic", "fakedns"])
    tcp_settings = {
        "acceptProxyProtocol": False,
        "header": {"type": "none"},
    }
    stream_settings = StreamSettings(security="none", network="tcp", tcp_settings=tcp_settings)
    inbound = Inbound(
        enable=True,
        port=443,
        protocol="vless",
        settings=settings,
        stream_settings=stream_settings,
        sniffing=sniffing,
        remark=inbound_name,
    )
    await api.inbound.add(inbound)
    inbound = [n for n in list(await api.inbound.get_list()) if n.remark == inbound_name][0]

    ip = requests.get("http://ipwho.is").json()["ip"]

    client = Client(
        id=str(uuid.uuid4()),
        email=client_name,
        enable=True
    )

    await api.client.add(inbound.id, [client])
    inbound = [n for n in list(await api.inbound.get_list()) if n.remark == inbound_name][0]
    client = [n for n in inbound.settings.clients if n.email == client_name][0]
    link = f"vless://{client.id}@{ip}:{inbound.port}?type=tcp&security=none#server-inbound-server"

    pwd = str(uuid.uuid4())
    req = {
        "username": "admin",
        "password": "admin",
        "loginSecret": "",
        "oldUsername": "admin",
        "oldPassword": "admin",
        "newUsername": "admin",
        "newPassword": pwd,
    }
    await api.client._post(
        url=api.client._url("panel/setting/updateUser"),
        data=req,
        headers={}
    )

    secret = {
        "link": link,
        "api": "http://" + api_url,
        "login": "admin",
        "password": pwd,
        "inbound": inbound.id,
        "client": client.email,
    }

    with open(secret_path, "w") as f:
        json.dump(secret, f, indent=4)


def get_secret():
    with open(secret_path, 'r') as f:
        return json.load(f)


async def get_session():
    secret = get_secret()
    api = AsyncApi(host=secret["api"], username=secret["login"], password=secret["password"])
    await api.login()
    return api


async def get_stats() -> Client:
    session = await get_session()
    client = await session.client.get_by_email(client_name)
    return client


async def run_server():
    app = Flask(__name__)
    import logging
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)

    @app.route("/")
    def hello_world():
        return "<p>Hello, World!</p>"

    app.run(host="0.0.0.0", port="9443")


async def main():
    session_secret = uuid.uuid4()

    if not os.path.exists(secret_path):
        print(f"Initializing server at {api_url}...", end='')
        await init()
        print("[OK]")
    else:
        print(f"Loading server settings from {secret_path}")

    print("Trying to get stats...", end='')
    # print(get_secret()['link'])
    stats = await get_stats()
    print("[OK]")
    print()

    print(f"Total usage: {(stats.up + stats.down) / (1024 * 1000)}Mb")

    print(f"Session secret (for external connection): {session_secret}")
    ip = requests.get("http://ipwho.is").json()["ip"]
    print(f"Listening on: {ip}")

    await run_server()

    return


asyncio.run(main())
