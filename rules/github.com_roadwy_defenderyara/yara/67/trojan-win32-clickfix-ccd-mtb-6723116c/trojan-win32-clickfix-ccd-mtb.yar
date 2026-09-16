rule Trojan_Win32_ClickFix_CCD_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.CCD!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } 		$a_00_1 = {68 00 74 00 74 00 70 00 } 		$a_00_2 = {27 00 69 00 65 00 78 00 27 00 } 		$a_00_3 = {27 00 69 00 77 00 72 00 27 00 } 		$a_00_4 = {3b 00 26 00 24 00 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}