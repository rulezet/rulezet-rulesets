rule Trojan_Win32_QakBot_AN_MTB{
	meta:
		description = "Trojan:Win32/QakBot.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } 		$a_01_1 = {49 36 48 45 57 68 44 30 79 } 		$a_01_2 = {49 67 31 6d 5a 44 64 54 67 4e 35 } 		$a_01_3 = {4a 61 61 44 52 75 47 6f 37 6e 75 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}