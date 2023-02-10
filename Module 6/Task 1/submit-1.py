import os
import subprocess
from time import sleep

def gdb_write(proc, string):
    command = f"{string}\n".encode()
    
    # cannot use communicate() (not good for interactive IO)
    proc.stdin.write(command)
    proc.stdin.flush()

#def nonBlockRead(output):
    #fd = output.fileno()
    #fl = fcntl.fcntl(fd, fcntl.F_GETFL)
    #fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
    #try:
        #return output.read().decode('utf8')
    #except:
        #return ''

def gdb_read(proc):
    
    eof = False
    while not eof:  
        proc.stdout.flush()   
        output = proc.stdout.readline()
        
        if len(output) == 0:
            print('EOF')
            eof = True
        
        else:
            print('PRINTING')
            print(output.decode('utf8'))

    #for output in io.TextIOWrapper(proc.stdout, encoding="utf-8"):
        #print(output)

    #list_of_strings = [x.decode('utf-8') for x in iter(proc.stdout.readlines())]
    #print(list_of_strings)
    #stdout = ''

    #while proc.poll() is None:
        #stdout += nonBlockRead(proc.stdout)

    #we can probably save some time and just print it instead...
    #print(stdout)

    #stdout = stdout.splitlines()
    #for line in stdout:
        #print(line)
        
def reset():
    os.system("pkill -9 gdb")
    os.system("pkill -9 node")
    os.system("kill $(pgrep -f 'sp_server.py')")
    os.system("pkill -9 string_parser")
    sleep(1)
    

def init():
    #mimic initialisation steps in run script
    print("Start Initialisation")
    
    print("Starting Manager")
    os.system("/home/isl/t1/run_manager.sh")
    sleep(1)
    
    print("Starting Peripheral")
    os.system("/home/isl/t1/run_peripheral.sh")
    sleep(1)
    
    print("Starting StringParser (with gdb)")
    gdb_proc = subprocess.Popen(["gdb", "python3"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    sleep(1)
    
    # settings for gdb from handout
    gdb_write(gdb_proc, "set auto-load safe-path")
    gdb_write(gdb_proc, "set follow-fork-mode child")
    gdb_write(gdb_proc, "set pagination off")
    gdb_write(gdb_proc, "set breakpoint pending on")
    # gdb_write(gdb_proc, "set set stop-on-solib-events 1")
    # gdb_write(gdb_proc, "set confirm off")
    
    sleep(1)
    print("Initialisation Done")
    
    sleep(1)
    return gdb_proc

def terminate(proc):
    proc.terminate()
    os.system("pkill -9 gdb")
    sleep(1)

def task1():
    gdb_proc = init()
    print("Starting Task1")
    # gdb_write(gdb_proc,"add-symbol-file /home/isl/.local/lib/stringparser_core.so")
    
    # We can inspect content of shared library dinamically loaded by sp_server.py on Ghidra
    # In particular, look at stringParser function called by sp_server.py
    # objective is to change parameter in the function encrypting the message sent to M by SP
    
    # set (pending) breakpoint
    gdb_write(gdb_proc,"break gcm_crypt_and_tag")
    
    print("Starting sp_server")
    gdb_write(gdb_proc,"run /home/isl/t1/sp_server.py")
    sleep(1)
    
    # once every component is initialised as desired, RP can send its request
    print("Starting RP")
    os.system("/home/isl/t1/start.sh &")
    sleep(1)
    
    gdb_write(gdb_proc,"continue")
    gdb_write(gdb_proc,"print input")
    
    # in task 1 objective is to make SP issue key update command 
    gdb_write(gdb_proc,'set {char[45]} input = "<mes><action type=\\"key-update\\"/></mes>"')
    gdb_write(gdb_proc,"print input")
    
    gdb_write(gdb_proc,"continue")
    sleep(1)

    #gdb_read(gdb_proc)

    print('terminate gdb')
    terminate(gdb_proc)
    
    print('Task1 Done')

def task2():
    gdb_proc = init()
    print("Starting Task1")
    # gdb_write(gdb_proc,"add-symbol-file /home/isl/.local/lib/stringparser_core.so")
    
    # We can inspect content of shared library dinamically loaded by sp_server.py on Ghidra
    # In particular, look at stringParser function called by sp_server.py
    # objective is to change parameter in the function encrypting the message sent to M by SP
    
    # set (pending) breakpoint
    gdb_write(gdb_proc,"break gcm_crypt_and_tag")
    
    print("Starting sp_server")
    gdb_write(gdb_proc,"run /home/isl/t1/sp_server.py")
    sleep(1)
    
    # once every component is initialised as desired, RP can send its request
    print("Starting RP")
    os.system("/home/isl/t1/start.sh &")
    sleep(1)
    
    gdb_write(gdb_proc,"continue")
    gdb_write(gdb_proc,"print input")
    
    # in task2 objective is to make SP issue message m2
    # inspecting stringParser we see that a choice of message to send seems to be done in if block for a certain redirectAdmin value
    # in particuar, choice depends on redeemer selector value, which selects which value in redeemer array to pass to extractValues function
    # we can try to hardcode result of extractValues function in input variable, similarly to task1
    
    #gdb_write(gdb_proc,'set {char[20]} input = "redeemToken,d3c0y"')
    #gdb_write(gdb_proc,'set {char[20]} input = "redeemToken,f4k3"')
    #gdb_write(gdb_proc,'set {char[20]} input = "redeemToken,doublef4k3"')
    gdb_write(gdb_proc,'set {char[20]} input = "redeemToken,token"')
    gdb_write(gdb_proc,"print input")
    
    gdb_write(gdb_proc,"continue")
    sleep(1)

    # gdb_read(gdb_proc)

    print('terminate gdb')
    terminate(gdb_proc)
    
    print('Task2 Done')
    


if __name__ == "__main__":
    reset()
    task1()
    
    reset()
    task2()

    reset()
    os.system("/home/isl/t1/run.sh")

    print("END")
    
    exit()