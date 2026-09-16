rule Trojan_Win32_ClickFix_DDL_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DDL!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {63 00 61 00 74 00 63 00 68 00 7b 00 69 00 65 00 78 00 28 00 63 00 75 00 72 00 6c 00 } 		$a_00_1 = {69 00 65 00 78 00 28 00 69 00 72 00 6d 00 20 00 24 00 } 		$a_02_2 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-50] 24 00 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}