rule Trojan_Win32_ClickFix_HHV_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.HHV!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {28 00 5b 00 53 00 63 00 72 00 69 00 70 00 74 00 42 00 6c 00 6f 00 63 00 6b 00 5d 00 3a 00 3a 00 43 00 72 00 65 00 61 00 74 00 65 00 28 00 28 00 69 00 77 00 72 00 } 		$a_00_1 = {20 00 2d 00 4d 00 65 00 74 00 68 00 6f 00 64 00 20 00 50 00 4f 00 53 00 54 00 29 00 2e 00 43 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 29 00 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}