rule Trojan_Win32_ClickFix_DDM_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DDM!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,79 00 79 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } 		$a_00_1 = {2d 00 55 00 73 00 65 00 42 00 61 00 73 00 69 00 63 00 50 00 61 00 72 00 73 00 69 00 6e 00 67 00 } 		$a_00_2 = {2e 00 43 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 } 		$a_00_3 = {24 00 65 00 6e 00 76 00 3a 00 5f 00 } 	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*1) >=121
 
}