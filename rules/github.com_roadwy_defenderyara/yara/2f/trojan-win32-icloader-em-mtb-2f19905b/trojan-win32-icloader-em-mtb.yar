rule Trojan_Win32_ICLoader_EM_MTB{
	meta:
		description = "Trojan:Win32/ICLoader.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {2e 61 71 72 73 76 74 74 2e 31 2e 31 32 32 36 34 } 		$a_81_1 = {57 4e 65 74 47 65 74 43 6f 6e 6e 65 63 74 69 6f 6e 57 } 		$a_81_2 = {42 72 69 6e 67 57 69 6e 64 6f 77 54 6f 54 6f 70 } 		$a_81_3 = {43 73 72 43 6c 69 65 6e 74 43 61 6c 6c 53 65 72 76 65 72 } 		$a_81_4 = {61 6c 69 7a 65 54 68 75 6e 6b } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}