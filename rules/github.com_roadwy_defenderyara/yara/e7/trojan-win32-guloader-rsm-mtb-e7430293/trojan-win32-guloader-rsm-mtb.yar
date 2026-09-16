rule Trojan_Win32_GuLoader_RSM_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RSM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {53 74 61 74 65 72 20 42 72 6f 73 2e 20 48 6f 6c 64 69 6e 67 73 20 49 6e 63 2e } 		$a_81_1 = {56 69 61 63 6f 6d 20 49 6e 63 } 		$a_81_2 = {4d 65 61 64 57 65 73 74 76 61 63 6f 20 43 6f 72 70 6f 72 61 74 69 6f 6e } 		$a_81_3 = {6b 75 6e 64 65 62 72 65 76 65 74 2e 65 78 65 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}