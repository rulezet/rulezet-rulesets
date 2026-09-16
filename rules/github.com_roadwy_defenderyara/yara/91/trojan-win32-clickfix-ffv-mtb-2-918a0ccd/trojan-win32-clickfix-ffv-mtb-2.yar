rule Trojan_Win32_ClickFix_FFV_MTB_2{
	meta:
		description = "Trojan:Win32/ClickFix.FFV!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {2e 00 43 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 3b 00 20 00 69 00 65 00 78 00 20 00 24 00 } 		$a_02_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-50] 24 00 } 		$a_00_2 = {68 00 69 00 64 00 64 00 65 00 6e 00 } 	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}