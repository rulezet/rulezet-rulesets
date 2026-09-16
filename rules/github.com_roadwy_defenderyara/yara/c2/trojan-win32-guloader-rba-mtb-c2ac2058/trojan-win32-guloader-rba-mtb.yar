rule Trojan_Win32_GuLoader_RBA_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {75 64 76 6c 67 65 6c 73 65 73 76 69 6e 64 75 65 74 73 } 		$a_81_1 = {68 6f 65 6a 61 64 65 6c 65 6e } 		$a_81_2 = {73 65 6a 6c 62 61 61 64 73 } 		$a_81_3 = {68 69 67 68 63 6f 75 72 74 2e 65 78 65 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}