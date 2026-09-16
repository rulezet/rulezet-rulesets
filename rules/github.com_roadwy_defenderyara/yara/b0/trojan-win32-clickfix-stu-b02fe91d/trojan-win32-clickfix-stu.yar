rule Trojan_Win32_ClickFix_STU{
	meta:
		description = "Trojan:Win32/ClickFix.STU,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_00_0 = {7c 00 69 00 65 00 78 00 } 		$a_00_1 = {63 00 75 00 72 00 6c 00 } 		$a_00_2 = {68 00 74 00 74 00 70 00 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*-1000) >=2
 
}