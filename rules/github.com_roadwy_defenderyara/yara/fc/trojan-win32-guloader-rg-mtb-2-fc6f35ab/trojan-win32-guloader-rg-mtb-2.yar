rule Trojan_Win32_GuLoader_RG_MTB_2{
	meta:
		description = "Trojan:Win32/GuLoader.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {55 72 69 6e 76 65 6a 73 73 79 67 64 6f 6d 6d 65 6e 65 73 2e 53 69 67 } 		$a_01_1 = {55 6e 69 6e 73 74 61 6c 6c 5c 45 6c 69 64 65 72 65 64 65 } 		$a_01_2 = {41 62 6c 61 74 69 76 65 73 5c 45 79 65 73 69 67 68 74 2e 69 6e 69 } 		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 53 70 69 6f 6e 6b 61 6d 65 72 61 65 74 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}