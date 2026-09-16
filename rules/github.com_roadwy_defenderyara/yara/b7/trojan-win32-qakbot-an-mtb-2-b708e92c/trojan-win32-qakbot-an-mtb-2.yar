rule Trojan_Win32_QakBot_AN_MTB_2{
	meta:
		description = "Trojan:Win32/QakBot.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {44 48 6a 68 4b 4e 38 6a 31 } 		$a_01_1 = {44 61 74 4a 45 74 41 43 41 4b 57 } 		$a_01_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } 		$a_01_3 = {45 39 32 31 79 56 67 58 54 30 4a } 		$a_01_4 = {49 54 30 6c 56 6d 7a 33 } 		$a_01_5 = {4e 79 4d 6f 31 35 4d } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}