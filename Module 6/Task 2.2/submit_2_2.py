import sys
import os
import subprocess
import string

CHECK_CHAR = "E:0x401d7f:C:64:cmp dl, al" 
CHAR_CORRECT = "E:0x401d83:C:8:add dword ptr [rbp-0x8], 0x1"
CHAR_WRONG = "E:0x401d89:C:8:add dword ptr [rbp-0xc], 0x1"

# FINAL_CHECK_size = "E:0x40129b:C:64:cmp eax, dword ptr [rbp-0x30]"
# FINAL_CHECK_k = "E:0x4012a3:C:64:cmp eax, dword ptr [rbp-0x2c]"

RET_CORRECT = "E:0x401da9:C:19b:mov eax, 0x1"
RET_WRONG = "E:0x401db0:C:19b:mov eax, 0x0"

def extract_args(argv):

    id = argv[1]
    if not os.path.exists("/home/isl/t2_2/output/"):
        os.system("mkdir /home/isl/t2_2/output")

    output_file = f"/home/isl/t2_2/output/oput_{id}"

    samples_path = "/home/isl/t2_2/samples"

    if not os.path.exists(samples_path):
        os.system(f"mkdir {samples_path}")
    
    if not os.path.exists(f"{samples_path}/{id}"):
        os.system(f"mkdir {samples_path}/{id}")

    if not os.path.exists(f"{samples_path}/{id}/traces"):
        os.system(f"mkdir {samples_path}/{id}/traces")
    
    traceset_path = f"/home/isl/t2_2/samples/{id}/traces"
    
    # traceset = []
    # for f in os.listdir(traces_folder):
    #     trace_file = os.path.join(traces_folder, f)
    #     if os.path.isfile(trace_file):
    #         traceset.append(trace_file)

    return traceset_path, output_file

def get_trace(traceset_path, index):

    guess = string.ascii_lowercase[index]*32
    # if not os.path.exists(f"/home/isl/t2_2/samples/{id}/traces/{guess}.txt"):
        # process = subprocess.Popen(f"cd /home/isl/pin-3.11-97998-g7ecce2dac-gcc-linux-master/source/tools/SGXTrace && ../../../pin -t ./obj-intel64/SGXTrace.so -o /home/isl/t2_2/samples/{id}/traces/{guess}.txt -trace 1 -- /home/isl/t2_2/password_checker_2 {guess}", shell=True)
    os.system(f"cd /home/isl/pin-3.11-97998-g7ecce2dac-gcc-linux-master/source/tools/SGXTrace && ../../../pin -t ./obj-intel64/SGXTrace.so -o {traceset_path}/{guess}.txt -trace 1 -- /home/isl/t2_2/password_checker_2 {guess}")
        # processes.append(process)
    
    # output = [p.wait() for p in processes]

    trace_file = f"{traceset_path}/{guess}.txt"
    return trace_file

def inspect_trace (trace_file):
    guess = list()
    g = os.path.basename(trace_file)[:-4]

    correct = True
    j = 0
    with open(trace_file, "r") as f:
        lines = f.readlines()
        for i in range(0, len(lines)):
            if lines[i].strip() == CHECK_CHAR:
                if lines[i+2].strip() == CHAR_CORRECT:
                    guess.append(g[j])
                    i += 1
                    j += 1
                if lines[i+2].strip() == CHAR_WRONG:
                    guess.append("_")
                    i += 1
                    j += 1
            
            if lines[i].strip() == RET_CORRECT:
                return guess, correct, j
            if lines[i].strip() == RET_WRONG:
                return guess, not correct, j

def find_guess_length(guess):

    guess_length = 0
    for i in range(0, len(guess)):
        if guess[i] != "_":
            guess_length = i

    return guess_length            
                
def guess_password(traceset_path):
    guesses = []
    complete = True
    max_length = 0

    guess = []
    for i in range(0, 33):
        guess.append("_")

    for i in range (0, 26):
        trace_file = get_trace(traceset_path, i)
        guess_tmp, correct, psw_len = inspect_trace(trace_file)
        
        if correct == True:
            return guess_tmp, complete
        
        guesses.append(guess_tmp)
        
        # guess_length = find_guess_length(guess_tmp)
        # if guess_length > max_length:
        #     max_length = guess_length
    
        for i in range (0, len(guess_tmp)):
            if guess_tmp[i] != "_":
                guess[i] = guess_tmp[i]
        
        correct = True 
        for i in range (psw_len):
            if guess[i] == "_":
                correct = False
        
        if correct == True:
            return guess, complete
        else:
            correct == False
            continue
    # for c in guess:
    #     if c == "_":
    #         return guess, not complete

    return guess, complete
        

def write_guess(guess_tmp, flag, output_file):
    if flag == True:
        flag = "complete"
    else:
        flag = "partial"

    guess = ""
    guess = guess.join(guess_tmp)
    guess = guess.strip("_")
    
    string = f"{guess},{flag}"
    with open(output_file, "w") as f:
        f.write(string)


if __name__ == "__main__":
    
    print("Reading Traces")
    traceset_path, output_file = extract_args(sys.argv)

    print("Guessing Password")
    guess, flag = guess_password(traceset_path)

    print("Writing guess")
    write_guess(guess, flag, output_file)
