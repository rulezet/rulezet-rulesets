rule Trojan_Win32_Fragtor_NFR_MTB_2{
	meta:
		description = "Trojan:Win32/Fragtor.NFR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6e 70 65 6e 2e 62 61 74 } 		$a_01_1 = {68 61 6f 2e 77 7a 31 39 34 39 2e 63 6f 6d } 		$a_01_2 = {70 69 70 69 5f 64 61 65 5f 34 37 33 2e 65 78 65 } 		$a_01_3 = {68 68 6d 6d 73 73 7a 7a 7a 2e 69 6e 69 } 		$a_01_4 = {66 6a 69 65 6a 2e 6c 6f 67 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}