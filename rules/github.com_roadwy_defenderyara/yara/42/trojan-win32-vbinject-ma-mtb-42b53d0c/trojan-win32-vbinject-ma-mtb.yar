rule Trojan_Win32_VBInject_MA_MTB{
	meta:
		description = "Trojan:Win32/VBInject.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_03_0 = {fb fa 63 47 8c 7e ?? e6 e2 e6 08 } 		$a_01_1 = {bc 10 40 00 4c d7 40 00 04 36 40 00 f4 35 40 00 14 36 40 00 b8 36 40 00 1c d0 40 00 88 1d 40 00 c0 29 40 00 0a 11 40 00 da 10 40 } 		$a_01_2 = {50 72 6f 63 65 73 73 33 32 4e 65 78 74 } 		$a_01_3 = {67 65 74 68 6f 73 74 62 79 6e 61 6d 65 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=12
 
}