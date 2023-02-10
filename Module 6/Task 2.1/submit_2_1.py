import sys
import os
import string

CHECK_CHAR = "E:0x40120d:C:64:cmp dl, al"
CHAR_CORRECT = "E:0x401211:C:8:add dword ptr [rbp-0xc], 0x1"
CHAR_WRONG = "E:0x401217:C:19b:mov eax, dword ptr [rbp-0x14]"

ITERATION = "E:0x40127e:C:31b:sub dword ptr [rbp-0x10], 0x1"
END_LOOP = "E:0x401288:C:8:add dword ptr [rbp-0x14], 0x1"

FINAL_CHECK_size = "E:0x40129b:C:64:cmp eax, dword ptr [rbp-0x30]"
FINAL_CHECK_k = "E:0x4012a3:C:64:cmp eax, dword ptr [rbp-0x2c]"

RET_CORRECT = "E:0x4012a8:C:19b:mov eax, 0x1"
RET_WRONG = "E:0x4012af:C:19b:mov eax, 0x0"

def extract_args(argv):
    traceset_tmp = []
    for f in os.listdir(argv[1]):
        trace_file = os.path.join(argv[1], f)
        if os.path.isfile(trace_file):
            traceset_tmp.append(trace_file)

    traceset = sorted(traceset_tmp, key=len, reverse=True)

    id = argv[2]
    if not os.path.exists("/home/isl/t2_1/output/"):
        os.system("mkdir /home/isl/t2_1/output/")

    output_file = f"/home/isl/t2_1/output/oput_{id}"

    return traceset, output_file

def char_from_distance(old, distance):
    old_pos = string.ascii_lowercase.index(old)
    new_pos = (old_pos + distance) % 26
    new = string.ascii_lowercase[new_pos]
    return new

def exploit_distance(lines, char):
    distance = 0
    for i in range(0, len(lines)):
        if lines[i].strip() == ITERATION:
            distance += 1
        if lines[i].strip() == END_LOOP:
            return char_from_distance(char, distance)

def inspect_trace (trace_file):
    guess = list()
    g = os.path.basename(trace_file)[:-4] # remove .txt extension

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
                    curr_char = g[j]
                    guess.append(exploit_distance(lines[i+1:], curr_char))
                    i += 1
                    j += 1
            
            if lines[i].strip() == RET_CORRECT:
                return guess, correct
            if lines[i].strip() == RET_WRONG:
                if j < len(g):
                    return guess, correct
                else:
                    return guess, not correct

def find_length(traceset):
    found = False
    for trace_file in traceset:

        if found == True:
            break
        
        with open(trace_file, "r") as f:
            lines = f.readlines()
            for i in range(0, len(lines)):
                
                if lines[i].strip() == FINAL_CHECK_size:
                    if lines[i+5].strip() == FINAL_CHECK_k:
                        found = True
                        break
                    else:
                        found = False
                        break
    
    return found
                
def guess_password(traceset):
    complete = True
    trace_file = traceset[0]

    guess_tmp, correct = inspect_trace(trace_file)
    
    guess = ""
    guess = guess.join(guess_tmp)
    
    if correct == True:
        return guess, complete
    
    else: 
        psw_len_found = find_length(traceset[1:])

        if psw_len_found:
            return guess, complete
        else:
            return guess, not complete
        

def write_guess(guess, flag, output_file):
    if flag == True:
        flag = "complete"
    else:
        flag = "partial"
    
    string = f"{guess},{flag}"
    with open(output_file, "w") as f:
        f.write(string)


if __name__ == "__main__":

    print("Reading Traces")
    traceset, output_file = extract_args(sys.argv)

    print("Guessing Password")
    guess, flag = guess_password(traceset)

    print("Writing guess")
    write_guess(guess, flag, output_file)



