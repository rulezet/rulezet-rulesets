rule Trojan_Win32_Formbook_MK_MTB_3{
	meta:
		description = "Trojan:Win32/Formbook.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {52 69 6e 4b 65 72 79 67 6d 61 } 		$a_81_1 = {44 72 61 77 49 6e 63 69 73 75 72 65 36 34 } 		$a_81_2 = {44 69 73 61 62 6c 65 41 78 69 6c } 		$a_81_3 = {54 6f 47 61 6e 67 77 61 79 } 		$a_81_4 = {52 65 6a 65 63 74 53 65 6c 65 6e 69 75 6d 2e 64 6c 6c } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}