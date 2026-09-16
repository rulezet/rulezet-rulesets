rule Trojan_Win32_VBKrypt_DS_MTB{
	meta:
		description = "Trojan:Win32/VBKrypt.DS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {18 43 00 31 18 43 00 45 18 43 00 68 18 43 00 18 19 43 00 1d 19 43 00 1d 19 43 00 3c 19 43 00 4b 19 43 00 d1 19 43 00 73 } 		$a_01_1 = {b8 9c 54 b9 32 9f e7 85 02 9a 94 35 f9 47 95 89 7b 04 83 e2 31 ef 2a 4f ad 33 99 66 cf 11 b7 } 		$a_01_2 = {00 ac 10 34 47 67 3e 32 41 2b 1a 75 bb 2a f1 40 93 81 a1 19 15 6a 00 00 00 4c a4 99 17 89 dc ec bc 3b bd 2d 33 e2 } 		$a_01_3 = {0d 14 00 00 1e 00 27 2e 35 3c 44 4b 52 59 60 68 6f 00 78 7f 86 8e 95 9c 00 a4 ac } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=4
 
}