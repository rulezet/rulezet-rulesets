rule Trojan_Win32_Emotet_AD{
	meta:
		description = "Trojan:Win32/Emotet.AD,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {70 65 78 70 6c 6f 69 74 73 77 61 73 4f 53 4a 74 6f 54 68 65 } 		$a_01_1 = {74 68 65 70 72 65 76 69 6f 75 73 6c 79 6d 65 6d 6f 72 79 57 65 62 4b 69 74 43 68 72 6f 6d 65 59 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}