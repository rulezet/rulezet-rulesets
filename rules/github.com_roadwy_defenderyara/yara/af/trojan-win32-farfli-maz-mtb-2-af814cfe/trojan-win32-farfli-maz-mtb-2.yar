rule Trojan_Win32_Farfli_MAZ_MTB_2{
	meta:
		description = "Trojan:Win32/Farfli.MAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_01_0 = {cf d7 b8 5e e4 d6 96 1b be 1a 0e d7 ea 78 fc 75 ca be b7 97 82 74 7f 33 c7 c7 b9 b7 82 d3 96 22 } 		$a_01_1 = {3f 68 c9 6e 15 0e e6 5a 35 db d0 a8 78 5b 42 c3 e2 d6 3a 72 cf df 7f 5a f1 c8 30 1f a8 e4 e5 3a } 		$a_01_2 = {4d 00 79 00 50 00 6c 00 61 00 79 00 65 00 72 00 20 00 46 00 6f 00 72 00 20 00 4d 00 79 00 20 00 4c 00 6f 00 76 00 65 00 72 00 } 		$a_01_3 = {40 2e 74 68 65 6d 69 64 61 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*1) >=10
 
}