import threading
import subprocess
import time

def runTimeout(timeout, function, *args):
    time.sleep(timeout)
    function(*args)
def setTimeout(timeout, function, *args):
    handler = threading.Thread(target=runTimeout, args=(timeout,function,*args,))
    handler.start()
    return handler

def pipeCmds(cmds):
    ps = None
    for cmd in cmds:
        stdin = ps.stdout if ps else None
        ps = subprocess.run(cmd, input=stdin, stdout=subprocess.PIPE, shell=False)
    return ps.stdout.decode('ascii').strip()
def runCmd(cmd):
    ps = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
    return ps.stdout.decode('ascii').strip()
