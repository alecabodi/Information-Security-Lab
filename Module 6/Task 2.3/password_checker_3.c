#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
// #include <sys/stat.h>

#define MAX_PADDED_SIZE 31
#define MAX_SIZE 15

int check_password(char* padded_psw, char* guess, int guess_len) {
    
    // int psw_len = 30 - padded_psw_len;
    // int offset = 15 - psw_len;

	char padded_guess[MAX_PADDED_SIZE] = "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\0";
	for (int i = 0; i < guess_len;i++)
		sscanf(guess+i, "%c", &padded_guess[i+(15-guess_len)]);

	int sum = 0;
	
	for (int i = 0; i < MAX_PADDED_SIZE; i++) {
		// char a = *(padded_psw + i);
		// char b = padded_guess[i];
		// int identical = 1;
		// int out = 0;

		// printf("%c, %c, %d, %d", a, b, identical, out);

		// %rdi, %rsi, %rdx, %rcx, %r8, and %r9

		// a rbp-0x1d
		// b rbp-0x1e
		// identical rbp-0x24
		// out rbp-0x28

		// asm(
		// 	"mov -0x1d(%rbp), %al \n\t \
        //     mov -0x1e(%rbp), %bl \n\t \
        //     mov -0x24(%rbp), %cx \n\t \
        //     mov -0x28(%rbp), %dx \n\t \
        //     cmp %al, %bl \n\t \
        //     cmove %cx, %dx \n\t \
        //     mov %dx, -0x28(%rbp) \n\t");

		// printf("\n%d\n", out);

		sum += (*(padded_psw + i) == padded_guess[i])?1:0;

	}
	// {
	// 	// %rdi, %rsi, %rdx, %rcx, %r8, and %r9

	// 	// a rbp-0x14
	// 	// b rbp-0x18
	// 	// identical rbp-0x1c
	// 	// out rbp-0x20

	// 	int a = guess_len;
	// 	int b = psw_len;
	// 	int identical = sum;
	// 	int out = 0;

	// 	// printf("%c, %c, %d, %d", a, b, identical, out);

	// 	asm(
	// 		"mov -0x14(%rbp), %ax \n\t \
	// 		mov -0x18(%rbp), %bx \n\t \
	// 		mov -0x1c(%rbp), %cx \n\t \
	// 		mov -0x20(%rbp), %dx \n\t \
	// 		cmp %ax, %bx \n\t \
	// 		cmove %cx, %dx \n\t \
	// 		mov %dx, -0x20(%rbp) \n\t");

	// 	printf("\n%d\n", out);

	// 	sum = out;
	// }

	
	{
		// %rdi, %rsi, %rdx, %rcx, %r8, and %r9

		// a rbp-0x10
		// b rbp-0x14
		// identical rbp-0x18
		// out rbp-0x1c

		// int a = sum;
		// int b = MAX_PADDED_SIZE;
		// int identical = 1;
		// int out = 0;

		// printf("%c, %d, %d, %d", a, b, identical, out);

		// asm(
		// 	"mov -0x10(%rbp), %ax \n\t \
		// 	mov -0x14(%rbp), %bx \n\t \
		// 	mov -0x18(%rbp), %cx \n\t \
		// 	mov -0x1c(%rbp), %dx \n\t \
		// 	cmp %ax, %bx \n\t \
		// 	cmove %cx, %dx \n\t \
		// 	mov %dx, -0x1c(%rbp) \n\t");

		// printf("\n%d\n", out);

		return (sum == MAX_PADDED_SIZE)?1:0;
	}
} 

//assumptions: password only has small characters [a, z], maximum length is 15 characters
int main (int argc, char* argv[])	{

	if (argc != 3) {
		fprintf(stderr, "Usage: %s <password guess> <output_file>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	FILE* password_file;
	char password[MAX_PADDED_SIZE] = "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\0";

    
	size_t len = 0;
	char filename[] = "/home/isl/t2_3/password.txt";
	password_file = fopen (filename, "r");

	if (password_file == NULL) {
		perror("cannot open password file\n");
		exit(EXIT_FAILURE);
	}

	// fscanf(password_file, "%s", password);
	// getline(&password, &size, password_file);
	for (int i = 0; i < MAX_SIZE;i++)
		password[i] = fgetc(password_file);
	
	// struct stat sb;

	// if (stat(filename, &sb) == -1)
    // perror("stat");

	// len = (int) sb.st_size;

	int is_match = 0; 
	is_match = check_password(password, argv[1], strlen(argv[1]));
	
	FILE* output_file;
	output_file = fopen (argv[2], "wb");
	fputc(is_match, output_file);
	fclose(output_file);

	fclose(password_file);
	return 0;
}


