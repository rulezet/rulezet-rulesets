rule Trojan_Win32_ClickFix_ZFB{
	meta:
		description = "Trojan:Win32/ClickFix.ZFB,SIGNATURE_TYPE_CMDHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } 		$a_00_1 = {2d 00 77 00 } 		$a_00_2 = {63 00 75 00 72 00 6c 00 } 		$a_00_3 = {7c 00 69 00 65 00 78 00 } 	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2) >=8
 
}