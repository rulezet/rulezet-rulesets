rule Trojan_Win32_ClickFix_DDM_MTB_2{
	meta:
		description = "Trojan:Win32/ClickFix.DDM!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {24 00 65 00 6e 00 76 00 3a 00 74 00 6d 00 70 00 [0-10] 3b 00 69 00 72 00 6d 00 20 00 2d 00 75 00 72 00 69 00 20 00 27 00 68 00 74 00 74 00 70 00 } 		$a_02_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-50] 24 00 } 		$a_00_2 = {2d 00 46 00 6f 00 72 00 63 00 65 00 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}