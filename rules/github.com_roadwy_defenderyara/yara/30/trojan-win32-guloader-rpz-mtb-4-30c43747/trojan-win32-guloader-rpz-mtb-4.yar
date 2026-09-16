rule Trojan_Win32_Guloader_RPZ_MTB_4{
	meta:
		description = "Trojan:Win32/Guloader.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {66 6f 6f 74 69 65 73 2e 72 77 61 } 		$a_01_1 = {6e 6f 6e 63 68 61 72 67 65 61 62 6c 65 2e 66 61 6c } 		$a_01_2 = {73 69 6c 6b 65 70 61 70 69 72 73 2e 67 75 6c } 		$a_01_3 = {72 65 76 61 6c 69 64 65 72 69 6e 67 73 63 65 6e 74 72 65 73 2e 62 72 75 } 		$a_01_4 = {53 75 7a 61 6e 6e 61 68 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}