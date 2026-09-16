rule Trojan_Win32_Guloader_RPZ_MTB_3{
	meta:
		description = "Trojan:Win32/Guloader.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4d 61 64 6d 6f 64 65 72 65 6e 2e 64 6c 6c } 		$a_01_1 = {43 61 62 6d 65 6e 5c 61 66 68 75 64 65 74 } 		$a_01_2 = {77 6f 72 74 68 77 68 69 6c 65 6e 65 73 73 } 		$a_01_3 = {6f 76 65 72 6a 65 67 65 72 73 } 		$a_01_4 = {53 75 6b 6b 65 72 6b 75 67 6c 65 72 6e 65 73 32 30 31 2e 68 65 72 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}