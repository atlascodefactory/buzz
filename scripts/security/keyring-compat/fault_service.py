"""Test-only Secret Service: locked item, denied prompt, or provider exit.

No real secrets or user bus are used. A write attempt is recorded and fails.
"""
import os
from pathlib import Path
import sys
import dbus
import dbus.service
from dbus.mainloop.glib import DBusGMainLoop
from gi.repository import GLib

DBusGMainLoop(set_as_default=True)
mode, ready, writes = sys.argv[1:]
bus = dbus.SessionBus()
name = dbus.service.BusName("org.freedesktop.secrets", bus=bus)
def record(event):
    with open(writes + ".events", "a") as stream:
        stream.write(event + "\n")

SERVICE = "org.freedesktop.Secret.Service"
PROMPT = "org.freedesktop.Secret.Prompt"

class Service(dbus.service.Object):
    @dbus.service.method(SERVICE, in_signature="sv", out_signature="vo")
    def OpenSession(self, algorithm, client_key):
        record("OpenSession")
        assert algorithm == "dh-ietf1024-sha256-aes128-cbc-pkcs7"
        return dbus.Array([dbus.Byte(2)], signature="y", variant_level=1), dbus.ObjectPath("/session")

    @dbus.service.method(SERVICE, in_signature="a{ss}", out_signature="aoao")
    def SearchItems(self, attrs):
        record("SearchItems")
        assert attrs["service"] == "mesh-llm"
        return [], [dbus.ObjectPath("/item")]

    @dbus.service.method(SERVICE, in_signature="ao", out_signature="aoo")
    def Unlock(self, paths):
        record("Unlock")
        if mode == "locked":
            raise dbus.exceptions.DBusException("locked", name="org.freedesktop.Secret.Error.IsLocked")
        return [], dbus.ObjectPath("/prompt")

    @dbus.service.method("org.freedesktop.DBus.Properties", in_signature="s", out_signature="a{sv}")
    def GetAll(self, interface):
        return {}

    @dbus.service.method(SERVICE, in_signature="a{sv}s", out_signature="oo")
    def CreateCollection(self, properties, alias):
        Path(writes).write_text("unexpected CreateCollection")
        raise dbus.exceptions.DBusException("unexpected write")

class Collection(dbus.service.Object):
    @dbus.service.method("org.freedesktop.Secret.Collection", in_signature="a{sv}(oayays)b", out_signature="oo")
    def CreateItem(self, properties, secret, replace):
        Path(writes).write_text("unexpected CreateItem")
        raise dbus.exceptions.DBusException("unexpected write")

class Prompt(dbus.service.Object):
    @dbus.service.method(PROMPT, in_signature="s", out_signature="")
    def Prompt(self, window):
        record("Prompt")
        if mode == "disconnect":
            def leave():
                record("exit")
                os._exit(0)
            GLib.timeout_add(100, leave)
        else:
            GLib.timeout_add(100, self.deny)

    def deny(self):
        record("Completed")
        self.Completed(mode != "approved", dbus.Array([], signature="o", variant_level=1))
        return False

    @dbus.service.signal(PROMPT, signature="bv")
    def Completed(self, dismissed, result):
        pass

class Item(dbus.service.Object):
    @dbus.service.method("org.freedesktop.Secret.Item", in_signature="(oayays)", out_signature="")
    def SetSecret(self, secret):
        Path(writes).write_text("unexpected write")
        raise dbus.exceptions.DBusException("unexpected write")

service = Service(bus, "/org/freedesktop/secrets")
prompt = Prompt(bus, "/prompt")
item = Item(bus, "/item")
collection = Collection(bus, "/collection")
Path(ready).touch()
GLib.MainLoop().run()
