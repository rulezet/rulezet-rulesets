rule Trojan_Win32_Caiijin{
	meta:
		description = "Trojan:Win32/Caiijin,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {69 6a 69 6e 67 63 61 69 2e 63 6f 6d 2f } 		$a_01_1 = {5c 64 72 69 76 65 72 73 5c 6d 73 72 78 6d 63 62 2e 73 79 73 } 		$a_01_2 = {5c 64 72 69 76 65 72 73 5c 74 64 61 63 2e 73 79 73 } 		$a_01_3 = {62 68 6f 62 68 6f 62 62 62 61 64 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}