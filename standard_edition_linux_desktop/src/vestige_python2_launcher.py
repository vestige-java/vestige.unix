#!/usr/bin/python2
import dbus
import dbus.bus
import dbus.service
import dbus.mainloop.glib
import gobject
import gtk
import gtk.gdk
import os
import signal
import gobject
import subprocess
import socket
import time
import struct
import fcntl


def addCA(path, db_name):
    child_pid = os.fork()
    if child_pid != 0:
        os.waitpid(child_pid, 0)
        return

    try:
        from nss.error import NSPRError
        import nss.error as nss_error
        import nss.nss as nss
    
        nss.nss_init_read_write(db_name)
    
        certdb = nss.get_default_certdb()
        slot = nss.get_internal_key_slot()

        cert = None
        try:
            si = nss.read_der_from_file(path, True)
            cert = nss.Certificate(si, certdb, True, None)
        except NSPRError as e:
            if e.error_code == nss_error.SEC_ERROR_INVALID_ARGS:
                # try pem
                si = nss.read_der_from_file(path, False)
                cert = nss.Certificate(si, certdb, True, None)

        if cert is not None:
            cert.set_trust_attributes("CT,C,C", certdb, slot)

        del cert
        del slot

        nss.nss_shutdown()
    finally:
        os._exit(0)

def addP12(path, db_name):
    child_pid = os.fork()
    if child_pid != 0:
        os.waitpid(child_pid, 0)
        return

    try:
        from nss.error import NSPRError
        import nss.error as nss_error
        import nss.nss as nss

        nss.nss_init_read_write(db_name)
        certdb = nss.get_default_certdb()
        slot = nss.get_internal_key_slot()

        nss.pkcs12_enable_all_ciphers()
        pkcs12 = nss.PKCS12Decoder(path, "changeit", slot)
        pkcs12.database_import()

        del pkcs12
        del slot

        nss.nss_shutdown()
    finally:
        os._exit(0)

def decodeBytesUtf8Safe(toDec):
    okLen = len(toDec)
    outStr = ""
    while okLen>0:
        try:
            outStr = toDec[:okLen].decode("UTF-8")
        except UnicodeDecodeError as ex:
            okLen -= 1
        else:
            break
    return outStr,toDec[okLen:]

class Vestige(dbus.service.Object):
    def __init__(self, bus, path, name):
        dbus.service.Object.__init__(self, bus, path, name)
        self.procState = 0
        self.openCount = 0
        self.running = False
        self.url = None
        self.loadStatusIcon = False
        self.consoleWinShown = False
        self.quit = False
        self.forceStop = False
        self.autostartPath = os.getenv("XDG_CONFIG_HOME", os.getenv("HOME") + "/.config") + "/autostart/vestige.desktop" 
        
        self.buffer = ""
        self.bufferRemain = 0
        self.bufferSize = 0
        self.bufferSizeBytes = 0

        self.consoleBuffer = ""

        if not os.environ.get("DESKTOP_SESSION", "").lower().startswith("gnome") or not "deprecated" in os.environ.get("GNOME_DESKTOP_SESSION_ID", ""):
            try:
                import appindicator
                self.ind = appindicator.Indicator("vestige", "/usr/share/icons/hicolor/scalable/apps/vestige.svg", appindicator.CATEGORY_APPLICATION_STATUS)
                self.ind.set_status(appindicator.STATUS_ACTIVE)
                self.ind.set_menu(gtk.Menu());
            except ImportError:
                # appindicator not found
                self.loadStatusIcon = True
        else:
            # gnome 3 status icon has a scrolling bug which occurs with appindicator fallback implementation
            self.loadStatusIcon = True

        if self.loadStatusIcon:
            self.statusicon = gtk.StatusIcon()
            self.statusicon.set_from_icon_name("vestige")
            self.statusicon.connect("popup-menu", self.right_click_event)
            self.statusicon.connect("activate", self.left_click_event)
            self.statusicon.set_tooltip("Vestige")


        self.consoleWin = gtk.Window()
        self.consoleWin.set_title("Vestige: command line output")
        self.consoleWin.set_default_size(700, 500)
        self.consoleWin.set_position(gtk.WIN_POS_CENTER_ALWAYS)
        self.consoleWin.connect('delete-event', lambda w, e : self.hideWin())
        self.console = gtk.TextView()
        self.console.set_editable(False)
        scroller = gtk.ScrolledWindow()
        scroller.add(self.console)
        self.consoleWin.add(scroller)

        self.menu = gtk.Menu()

        self.adminItem = gtk.MenuItem("Open web administration")
        self.adminItem.connect("activate", lambda e : self.showAdmin())
        self.menu.append(self.adminItem)
        self.adminItem.set_sensitive(False)

        self.folderItem = gtk.MenuItem("Open config folder")
        self.folderItem.connect("activate", lambda e : self.openFolder())
        self.menu.append(self.folderItem)
        self.folderItem.set_sensitive(False)

        serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        serversocket.bind(('127.0.0.1', 0))
        serversocket.listen(1)
        gobject.io_add_watch(serversocket, gobject.IO_IN, self.listener)

        procenv = os.environ.copy()

        procenv["VESTIGE_LISTENER_PORT"] = str(serversocket.getsockname()[1])
        procenv["VESTIGE_CONSOLE_ENCODING"] = "UTF-8"
        try:
            self.proc = subprocess.Popen("/usr/share/vestige/vestige", env=procenv, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            fcntl.fcntl(self.proc.stdout, fcntl.F_SETFL, fcntl.fcntl(self.proc.stdout, fcntl.F_GETFL, 0) | os.O_NONBLOCK)
            fcntl.fcntl(self.proc.stderr, fcntl.F_SETFL, fcntl.fcntl(self.proc.stderr, fcntl.F_GETFL, 0) | os.O_NONBLOCK)
            
            gobject.io_add_watch(self.proc.stdout, gobject.IO_IN, self.write_to_buffer)
            gobject.io_add_watch(self.proc.stderr, gobject.IO_IN, self.write_to_buffer)
            gobject.child_watch_add(self.proc.pid, lambda pid, condition: self.processQuit())
        except:
            buf = self.console.get_buffer()
            buf.insert_at_cursor("Error: vestige script cannot be launched")
            self.processQuit();


        consoleItem = gtk.MenuItem("Show command line output")
        consoleItem.connect("activate", lambda e : self.showWin())
        self.menu.append(consoleItem)

        self.startAtLoginItem = gtk.CheckMenuItem("Start at login")
        self.startAtLoginItem.set_active(os.path.isfile(self.autostartPath))
        self.startAtLoginItem.connect("activate", self.toggleStartAtLogin);
        self.menu.append(self.startAtLoginItem)

        self.menu.append(gtk.SeparatorMenuItem())

        self.stopItem = gtk.MenuItem("Stop")
        self.stopItem.connect("activate", lambda e : self.stopVestige())
        self.menu.append(self.stopItem)

        self.menu.show_all()

        if not self.loadStatusIcon:
            self.ind.set_menu(self.menu)


    def processQuit(self):
        if not self.quit and (self.consoleWinShown or self.procState < 2):
            # user show console or starting failed
            self.procState = 5
            if self.loadStatusIcon:
                self.statusicon.set_visible(False)
            else:
                import appindicator
                self.ind.set_status(appindicator.STATUS_PASSIVE)
            self.showWin();
        else:
            gtk.main_quit()

    def quitVestige(self):
        self.quit = True
        if self.procState == 5:
            gtk.main_quit()
        else:
            self.proc.terminate()
            self.stopItem.set_label("Force stop")
            self.forceStop = True

    def stopVestige(self):
        try:
            if self.proc is not None:
                if self.forceStop:
                    self.proc.kill()
                else:
                    self.proc.terminate();
                    self.stopItem.set_label("Force stop")
                    self.forceStop = True
        except:
            pass

    def toggleStartAtLogin(self, widget):
        # seems that widget change its state before calling activate
        if widget.active:
            autostartPathDirname = os.path.dirname(self.autostartPath)
            if not os.path.exists(autostartPathDirname):
                os.makedirs(autostartPathDirname)
            os.symlink('/usr/share/applications/vestige.desktop', self.autostartPath)
        else:
            try:
                os.remove(self.autostartPath)
            except:
                pass

    def openFolder(self):
        env = os.environ.copy()
        self.openCount += 1
        env["DESKTOP_STARTUP_ID"] = "vestige-xdg_open-%d_TIME%d" % (self.openCount, time.time())
        subprocess.Popen(["xdg-open", self.baseFolder], env=env)

    def showAdmin(self):
        env = os.environ.copy()
        self.openCount += 1
        env["DESKTOP_STARTUP_ID"] = "vestige-xdg_open-%d_TIME%d" % (self.openCount, time.time())
        subprocess.Popen(["xdg-open", self.url], env=env)

    def showWin(self):
        self.consoleWinShown = True
        self.consoleWin.show_all()
        self.consoleWin.present_with_time(int(time.time()))
        self.consoleWin.window.focus()

    def hideWin(self):
        if self.procState == 5:
            gtk.main_quit()
        else:
            self.consoleWinShown = False
            self.consoleWin.hide();
        return True

    def listener(self, sock, arg):
        conn, addr = sock.accept()
        sock.close()
        gobject.io_add_watch(conn, gobject.IO_IN, self.handler)
        return False

    def handler(self, conn, args):
        if self.bufferSizeBytes != 4:
            nbuffer = conn.recv(4 - self.bufferSizeBytes)
            if not len(nbuffer):
                return False
            
            self.bufferSizeBytes += len(nbuffer)
            self.buffer += nbuffer
            if self.bufferSizeBytes != 4:
                return True
            self.bufferSize = struct.unpack('!i', self.buffer)[0]
            self.buffer = ""
            self.bufferRemain = self.bufferSize
            return True;

        nbuffer = conn.recv(self.bufferRemain)
        if not len(nbuffer):
            return False

        self.bufferRemain -= len(nbuffer)
        self.buffer += nbuffer
        
        if self.bufferRemain != 0:
            return True;
        self.bufferSizeBytes = 0;
            
        line = self.buffer.decode("UTF-8")
        self.buffer = ""
                    
        if line.startswith("Web "):
            self.url = line[len("Web "):]
            self.adminItem.set_sensitive(True)
        elif line.startswith("Config "):
            self.baseFolder = line[len("Config "):]
            self.folderItem.set_sensitive(True)
        elif line == "Starting":
            self.procState = 1
        elif line == "Started":
            self.procState = 2
        elif line == "Stopping":
            self.procState = 3
        elif line == "Stopped":
            self.procState = 4
        elif line.startswith("CA "):
            for firefoxdir in [os.getenv("HOME") + "/.mozilla/firefox", os.getenv("XDG_DATA_HOME", os.getenv("HOME") + "/.local/share") + "/mozilla/firefox"]:
                if os.path.isdir(firefoxdir):
                    files = os.listdir(firefoxdir)
                    for name in files:
                        sqldb = firefoxdir + "/" + name
                        if os.path.isfile(sqldb + "/cert9.db"):
                            addCA(line[len("CA "):], "sql:" + sqldb)

            for nssdir in ["sql:" + os.getenv("HOME") + "/.pki/nssdb", "sql:" + os.getenv("HOME") + "/snap/chromium/current/.pki/nssdb"]:
                addCA(line[len("CA "):], nssdir)
        elif line.startswith("ClientP12 "):
            for firefoxdir in [os.getenv("HOME") + "/.mozilla/firefox", os.getenv("XDG_DATA_HOME", os.getenv("HOME") + "/.local/share") + "/mozilla/firefox"]:
                if os.path.isdir(firefoxdir):
                    files = os.listdir(firefoxdir)
                    for name in files:
                        sqldb = firefoxdir + "/" + name
                        if os.path.isfile(sqldb + "/cert9.db"):
                            addP12(line[len("ClientP12 "):], "sql:" + sqldb);

            for nssdir in ["sql:" + os.getenv("HOME") + "/.pki/nssdb", "sql:" + os.getenv("HOME") + "/snap/chromium/current/.pki/nssdb"]:
                addP12(line[len("ClientP12 "):], nssdir)
        return True

    def write_to_buffer(self, fd, condition):
        if condition == gobject.IO_IN:
            r = fd.read(1024)
            self.consoleBuffer += r

            decoded, self.consoleBuffer = decodeBytesUtf8Safe(self.consoleBuffer)
            buf = self.console.get_buffer()
            buf.place_cursor(buf.get_end_iter());
            buf.insert_at_cursor(decoded)
            return True
        else:
            return True

    def left_click_event(self, icon):
        self.menu.popup(None, None, None, 0, gtk.get_current_event_time(), icon)

    def right_click_event(self, icon, button, activate_time):
        self.menu.popup(None, None, None, button, activate_time, icon)

    @dbus.service.method("fr.gaellalire.vestige", in_signature='', out_signature='')
    def handleFiles(self):
        # TODO add file name array
        pass

app = None
def signalHandler(signal, frame):
    if app is not None:
        app.quitVestige();

signal.signal(signal.SIGTERM, signalHandler)
signal.signal(signal.SIGINT, signalHandler)
try:
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SessionBus()
    local = False
    request = bus.request_name("fr.gaellalire.vestige", dbus.bus.NAME_FLAG_DO_NOT_QUEUE)
    if request != dbus.bus.REQUEST_NAME_REPLY_EXISTS:
        app = Vestige(bus, '/', "fr.gaellalire.vestige")
        local = True
    else:
        object = bus.get_object("fr.gaellalire.vestige", "/")
        app = dbus.Interface(object, "fr.gaellalire.vestige")

    app.handleFiles()
    gtk.gdk.notify_startup_complete()

    if local:
        gtk.main()
except KeyboardInterrupt:
    if app is not None:
        app.quitVestige();
