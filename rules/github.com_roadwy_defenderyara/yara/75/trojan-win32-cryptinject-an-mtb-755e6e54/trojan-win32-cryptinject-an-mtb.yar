rule Trojan_Win32_CryptInject_AN_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 7a 6a 66 61 7a 6b 72 69 66 62 6a } 		$a_01_1 = {6d 52 5a 56 4f 5a 71 41 4f 4c 57 6e 52 6f 4f } 		$a_01_2 = {72 6d 68 75 6c 7a 73 77 76 6e 6a 64 68 79 } 		$a_01_3 = {78 65 5a 58 48 65 51 6b 66 77 43 68 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}