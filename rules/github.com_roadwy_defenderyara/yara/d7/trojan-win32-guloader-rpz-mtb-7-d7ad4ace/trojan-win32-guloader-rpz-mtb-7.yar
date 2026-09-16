rule Trojan_Win32_Guloader_RPZ_MTB_7{
	meta:
		description = "Trojan:Win32/Guloader.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_01_0 = {6f 76 65 72 77 69 74 68 65 72 65 64 2e 76 65 72 } 		$a_01_1 = {66 61 72 76 65 68 61 6e 64 6c 65 6e 73 2e 6d 65 74 } 		$a_01_2 = {43 61 72 64 69 6e 61 6c 73 68 69 70 5c 69 6e 64 74 72 6e 67 65 6e 64 65 2e 74 69 6c } 		$a_01_3 = {53 74 6f 72 6d 65 6e 64 65 5c 50 65 6a 6c 65 74 31 38 34 } 		$a_01_4 = {69 6d 6d 75 6e 6f 6c 6f 67 69 73 2e 42 79 67 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=14
 
}