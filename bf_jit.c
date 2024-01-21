#include<stdio.h>
#include<stdlib.h>
#include<sys/mman.h>
#include<string.h>

typedef struct {
	void *code;
	size_t code_size;
	size_t offset_to_address;
} Op;

typedef struct {
	Op left;
	Op right;
	Op inc;
	Op dec;
	Op output;
	Op input;
	Op jump_if_zero;
	Op jump_if_not_zero;
	Op exit;
} OpCodes;

typedef struct {
	unsigned char *data;
	size_t count;
	size_t size;
	size_t *addresses_to_update;
	size_t count_addresses_to_update;
	size_t size_addresses_to_update;
} Code ;

void append_code(Code *code, Op* op) {
	if (code->size - code->count < op->code_size) {
		size_t newsize = code->size + 2048;
		while (newsize - code->count - op->code_size < 0) {
			newsize += 1024;
		}
		code->data = realloc(code->data, newsize);
		code->size = newsize;
	}
	memcpy(code->data + code->count, op->code, op->code_size);
	code->count += op->code_size;

	if (op->offset_to_address > 0) {
		if (code->size_addresses_to_update - code->count_addresses_to_update <= 0) {
			size_t newsize = code->size_addresses_to_update + 64;
			code->addresses_to_update = realloc(code->addresses_to_update, newsize * sizeof(void*));
			code->size_addresses_to_update = newsize;
		}
		code->addresses_to_update[code->count_addresses_to_update++] = code->count - op->code_size + op->offset_to_address;
	}
}

void compile_ops(Code *code, FILE *file, OpCodes *codes, int end) {
	size_t start_count = code->count;
	int read;
	while((read = getc(file)) != EOF) {
		unsigned char op = (unsigned char)read;
		switch(op) {
			case '>': append_code(code, &codes->right); break;
			case '<': append_code(code, &codes->left); break;
			case '+': append_code(code, &codes->inc); break;
			case '-': append_code(code, &codes->dec); break;
			case '.': append_code(code, &codes->output); break;
			case ',': append_code(code, &codes->input); break;
			case '[': {
				size_t prev_count = code->count;
				append_code(code, &codes->jump_if_zero);
				compile_ops(code, file, codes, ']');
				//Set offset to after enclosed block
				*(void**)(code->data + prev_count + codes->jump_if_zero.offset_to_address) = (void*)code->count;
				break;
			}
			case ']': {
				size_t prev_count = code->count;
				append_code(code, &codes->jump_if_not_zero);
				//Set offset to begin of block
				*(void**)(code->data + prev_count + codes->jump_if_not_zero.offset_to_address) = (void*)start_count;
				goto end;
			}
			default: continue;
		}
	}
	end:
	if (read != end) {
		fprintf(stderr, "Inbalanced parantheses!\n");
		exit(1);
	}
}

typedef void *compiled_assembly(unsigned char *);

compiled_assembly *compile(const char *filename, OpCodes* codes) {
	Code code = {0};
	FILE *file = fopen(filename, "r");
	if (!file) {
		fprintf(stderr, "Cannot open file %s\n", filename);
		exit(1);
	}
	compile_ops(&code, file, codes, EOF);
	append_code(&code, &codes->exit);
	fclose(file);

	void * assembly = mmap(NULL, code.count,  PROT_EXEC | PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	memcpy(assembly, code.data, code.count);
	// Backpatch offset to memory region:
	for (int i = 0; i < code.count_addresses_to_update; ++i) {
		void **loc = (void**)(assembly + code.addresses_to_update[i]);
		size_t offset = (size_t)*(void**)loc;
		*loc = (unsigned char*)assembly + offset;
	}
	if (code.data) {
		free(code.data);
	}
	if (code.addresses_to_update) {
		free(code.addresses_to_update);
	}
	return assembly;
}

int findLength(void *start) {
	unsigned char *p = start;
	while (*p++ != 0xC3) {}// x86 Return
	return p - 1 - (unsigned char*)start;
}

int findAddressOffset(void *start, size_t len) {
	void *needleContent = (void*)0xDEADBEEFDEADBEEF;
	char *needle = (char*)&needleContent;
	size_t needleSize = sizeof(needleContent);
	char *haystack = (char *)start;
	for (int i = 0; i < len - needleSize; ++i) {
		if (memcmp(haystack + i, needle, needleSize) == 0) {
			return i;
		}
	}

	return 0;
}

extern void code_right();
extern void code_left();
extern void code_inc();
extern void code_dec();
extern void code_output();
extern void code_input();
extern void code_jump_if_zero();
extern void code_jump_if_not_zero();
extern void code_exit();

asm("\n"
"code_left: \n"
"	subq $1, %rdi\n"
"	ret\n"
"code_right: \n"
"	addq $1, %rdi\n"
"	ret\n"
"code_inc: \n"
"	addb $1, (%rdi)\n"
"	ret\n"
"code_dec: \n"
"	subb $1, (%rdi)\n"
"	ret\n"
"code_output: \n"
"	push %rdi\n"
"	mov $1, %rax\n"
"	mov %rdi, %rsi\n"
"	mov $1, %rdi\n"
"	mov $1, %rdx\n"
"	syscall\n"
"	pop %rdi\n"
"	ret\n"
"code_input: \n"
"	push %rdi\n"
"	mov $0, %rax\n"
"	mov %rdi, %rsi\n"
"	mov $0, %rdi\n"
"	mov $1, %rdx\n"
"	syscall\n"
"	pop %rdi\n"
"	ret\n"
"code_jump_if_zero: \n"
"	cmpb $0, (%rdi)\n"
"	jne .notzero\n"
"	movq $0xDEADBEEFDEADBEEF, %rax\n"
"	jmp *%rax\n"
".notzero:\n"
"	ret\n"
"code_jump_if_not_zero: \n"
"	cmpb $0, (%rdi)\n"
"	je .zero\n"
"	movq $0xDEADBEEFDEADBEEF, %rax\n"
"	jmp *%rax\n"
".zero:\n"
"code_exit: \n"
"	ret\n"
);


int main(int argc, const char *argv[]) {
	if (argc != 2) {
		fprintf(stderr, "Usage: %s [filename]\n", argv[0]);
		exit(1);
	}

	OpCodes codes = {
		{code_left, findLength(code_left), 0},
		{code_right, findLength(code_right), 0},
		{code_inc, findLength(code_inc), 0},
		{code_dec, findLength(code_dec), 0},
		{code_output, findLength(code_output), 0},
		{code_input, findLength(code_input), 0},
		{code_jump_if_zero, findLength(code_jump_if_zero), 0},
		{code_jump_if_not_zero, findLength(code_jump_if_not_zero), 0},
		{code_exit, 1, 0}, // Assumes `ret` is only a single byte.
	};
	codes.jump_if_zero.offset_to_address = findAddressOffset(code_jump_if_zero, codes.jump_if_zero.code_size);
	codes.jump_if_not_zero.offset_to_address = findAddressOffset(code_jump_if_not_zero, codes.jump_if_not_zero.code_size);

	const char * filename = argv[1];
	compiled_assembly *compiled_code = compile(filename, &codes);
	unsigned char *memory = calloc(30000, 1);
	compiled_code(memory);
	free(memory);
	return 0;
}
