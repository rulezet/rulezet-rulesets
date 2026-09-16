rule Trojan_Win32_Small_EM_MTB_3{
	meta:
		description = "Trojan:Win32/Small.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4c 01 03 00 a0 43 e2 34 } 		$a_81_1 = {55 6e 6d 61 70 56 69 65 77 4f 66 46 69 6c 65 } 		$a_81_2 = {4d 61 70 56 69 65 77 4f 66 46 69 6c 65 } 		$a_81_3 = {4f 70 65 6e 46 69 6c 65 4d 61 70 70 69 6e 67 41 } 		$a_81_4 = {44 52 41 4d 4d 41 50 } 	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}