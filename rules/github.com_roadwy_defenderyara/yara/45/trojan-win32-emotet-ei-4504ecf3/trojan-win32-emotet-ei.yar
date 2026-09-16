rule Trojan_Win32_Emotet_EI{
	meta:
		description = "Trojan:Win32/Emotet.EI,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {42 59 5f 45 4d 4f 54 45 54 2e 31 } 		$a_01_1 = {50 59 5f 45 4d 4f 54 45 54 } 		$a_01_2 = {23 23 23 23 23 23 23 23 23 23 28 28 28 28 29 29 29 29 29 63 4f 64 65 2d 50 41 53 53 57 4f 52 44 21 21 21 2e 70 64 62 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}