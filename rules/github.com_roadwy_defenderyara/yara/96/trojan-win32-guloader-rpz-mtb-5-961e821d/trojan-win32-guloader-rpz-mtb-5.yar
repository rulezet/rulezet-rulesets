rule Trojan_Win32_Guloader_RPZ_MTB_5{
	meta:
		description = "Trojan:Win32/Guloader.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {54 65 6e 6e 69 73 65 6e 73 5c 6e 6f 6e 6d 61 6c 6c 65 61 62 6e 65 73 73 } 		$a_01_1 = {75 6e 69 6d 6d 6f 72 74 61 6c 69 73 65 64 } 		$a_01_2 = {6c 65 74 68 61 6c 69 74 79 5c 64 69 61 73 73 65 6e 65 } 		$a_01_3 = {72 65 67 72 69 70 70 65 64 5c 6c 69 70 70 69 6e 67 73 2e 77 69 74 } 		$a_01_4 = {6b 76 61 64 72 75 70 65 6c } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}