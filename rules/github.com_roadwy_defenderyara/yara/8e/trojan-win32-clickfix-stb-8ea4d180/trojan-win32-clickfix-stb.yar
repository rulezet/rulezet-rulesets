rule Trojan_Win32_ClickFix_STB{
	meta:
		description = "Trojan:Win32/ClickFix.STB,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {6d 00 73 00 68 00 74 00 61 00 } 		$a_00_1 = {20 00 23 00 20 00 } 		$a_00_2 = {3a 00 2f 00 2f 00 } 		$a_00_3 = {2e 00 6f 00 67 00 67 00 20 00 23 00 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}