rule Trojan_Win32_ClickFix_ZE{
	meta:
		description = "Trojan:Win32/ClickFix.ZE,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {6d 00 73 00 68 00 74 00 61 00 } 		$a_00_1 = {68 00 74 00 74 00 70 00 } 		$a_00_2 = {32 00 6e 00 6f 00 2e 00 63 00 6f 00 2f 00 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}