rule Trojan_Win32_ClickFix_ZF_2{
	meta:
		description = "Trojan:Win32/ClickFix.ZF,SIGNATURE_TYPE_CMDHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } 		$a_00_1 = {2d 00 77 00 } 		$a_00_2 = {68 00 74 00 74 00 70 00 } 		$a_00_3 = {63 00 75 00 72 00 6c 00 } 		$a_00_4 = {2e 00 70 00 73 00 31 00 } 	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*-5000) >=8
 
}