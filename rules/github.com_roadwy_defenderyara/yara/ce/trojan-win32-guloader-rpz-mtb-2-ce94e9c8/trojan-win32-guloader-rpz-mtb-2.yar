rule Trojan_Win32_Guloader_RPZ_MTB_2{
	meta:
		description = "Trojan:Win32/Guloader.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 6f 72 70 6f 72 61 32 32 30 2e 46 69 6c } 		$a_01_1 = {62 65 73 74 6e 69 6e 67 73 6d 65 64 6c 65 6d 2e 63 68 61 } 		$a_01_2 = {70 6f 6c 6c 69 6e 6f 73 69 73 2e 4b 74 74 } 		$a_01_3 = {75 6e 73 77 61 79 61 62 6c 65 6e 65 73 73 } 		$a_01_4 = {73 69 64 65 68 6e 67 74 65 2e 69 6e 69 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}