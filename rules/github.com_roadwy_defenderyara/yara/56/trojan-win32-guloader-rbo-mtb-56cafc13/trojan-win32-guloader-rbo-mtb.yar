rule Trojan_Win32_GuLoader_RBO_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RBO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {43 6f 63 61 2d 43 6f 6c 61 20 45 6e 74 65 72 70 72 69 73 65 73 20 49 6e 63 2e } 		$a_81_1 = {4f 75 74 62 61 63 6b 20 53 74 65 61 6b 68 6f 75 73 65 20 49 6e 63 2e } 		$a_81_2 = {4d 61 78 69 6d 20 49 6e 74 65 67 72 61 74 65 64 20 50 72 6f 64 75 63 74 73 20 49 6e 63 2e } 		$a_81_3 = {64 69 6d 69 6e 69 73 68 6d 65 6e 74 2e 65 78 65 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}