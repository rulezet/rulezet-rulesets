rule Trojan_Win32_ClickFix_IIP_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.IIP!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {6e 00 75 00 6c 00 26 00 63 00 75 00 72 00 6c 00 20 00 2d 00 } 		$a_00_1 = {63 00 6d 00 64 00 3e 00 6e 00 75 00 6c 00 } 		$a_00_2 = {65 00 6e 00 63 00 6f 00 64 00 65 00 3d 00 } 		$a_00_3 = {64 00 65 00 6c 00 20 00 2f 00 71 00 20 00 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}