import os
import subprocess
import csv 

guesses = ["magic", "party"]
correct = ["abcdefghijklmno", "", "magicbeans", "wholetmein"]
f = []
# sum = 0
wrong_op=0
out = []

def run_diff(file1, file2):
    str=os.popen('diff -q ./traces/'+file1+' ./traces/'+file2).read()
    return len(str)
sum = 0

def diff_all(guesses, correct):
    for c1 in correct:
        for g1 in guesses:
            f1 = g1 + '_' + c1 + '.txt'
            for c2 in correct:
                for g2 in guesses:
                    f2 = g2 + '_' + c2 + '.txt'
                    global sum
                    if f1 != f2:
                        diff = run_diff(f1,f2)
                        sum = sum + diff
                        out.append((g1, g2, c1, c2, diff))

def run_tracer(guess,correct):
    op = subprocess.Popen(['./run_single.sh '+guess+' '+guess+'_'+correct], shell=True)
    op.wait()

def hexdump():
    p='/home/isl/t2_3/oput'
    if(os.path.isfile(p)):
        cmd="hexdump -v -e '/1 \"%01X\"' "+p
        str=os.popen(cmd).read()
        return ord(str)
    else:
        return 47

def run_all_guesses(correct):
    for g in guesses:
        run_tracer(g, correct)
        o = hexdump()
        f.append((g, correct, o-48))
        global wrong_op
        if g == correct:
            if o != 49:
                wrong_op = wrong_op + 1
                print(g, correct, o, 1)
        else:
            if o != 48:
                wrong_op = wrong_op + 1
                print(g, correct, o, 0)


def run_correct_password():
    for c in correct:
        #create password.txt with c 
        l = 16 - len(c) - 1 
        d = '$'*l
        try:
            os.remove("../password.txt")
        except OSError:
            pass

        with open("../password.txt","w") as p:
            p.write(d+c+d)
        run_all_guesses(c)

# def load_testset():
#     global guesses
#     guesses.append("magic").\
#         append("qwert").\
#         append("pawnd")
    
#     global correct
#     correct.append("magicbeans").\
#     append("qwerty").\
#     append("magic")


def write_output():
    print(['guess','correct1', 'output'])
    for row in f:
        print(row)
    
    for row in out:
        print(row)

os.chdir("/home/isl/t2_3/test")
# load_testset()
run_correct_password()

if wrong_op == 0:
    print("The functionality is correct")
else:
    print("The functionality is wrong")

diff_all(guesses=guesses, correct=correct)

write_output()
