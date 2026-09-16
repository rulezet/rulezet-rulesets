rule Trojan_Win32_QakBot_RPR_MTB_2{
	meta:
		description = "Trojan:Win32/QakBot.RPR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {41 46 64 39 72 48 4d 31 61 } 		$a_01_1 = {42 61 74 61 4d 36 6f 68 6f 6f } 		$a_01_2 = {41 78 69 6f 39 50 35 57 } 		$a_01_3 = {43 4e 6e 45 50 78 } 		$a_01_4 = {43 5a 78 44 51 6b 56 } 		$a_01_5 = {44 59 63 66 43 42 78 53 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}