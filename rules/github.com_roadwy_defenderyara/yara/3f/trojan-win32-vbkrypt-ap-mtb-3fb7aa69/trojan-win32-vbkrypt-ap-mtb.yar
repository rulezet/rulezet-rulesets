rule Trojan_Win32_VBKrypt_AP_MTB{
	meta:
		description = "Trojan:Win32/VBKrypt.AP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {43 aa 31 86 11 04 f8 14 18 a4 16 2f 31 9d e4 e6 4b 2a db 81 a4 55 51 41 78 f8 1e e7 19 f9 12 00 6d fa aa 3f bc 31 90 c2 43 4f 73 } 		$a_01_1 = {46 33 f8 25 f7 05 44 f5 99 fe 21 a1 fb ad 6f 3f c3 53 32 60 a5 99 9e 4d fd 1e 23 36 0a 58 44 13 43 6f 7e } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}