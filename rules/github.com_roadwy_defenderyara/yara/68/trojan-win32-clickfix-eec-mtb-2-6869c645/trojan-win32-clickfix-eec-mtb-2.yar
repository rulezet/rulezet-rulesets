rule Trojan_Win32_ClickFix_EEC_MTB_2{
	meta:
		description = "Trojan:Win32/ClickFix.EEC!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {63 00 75 00 72 00 6c 00 20 00 2d 00 6f 00 } 		$a_00_1 = {2e 00 7a 00 69 00 70 00 20 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 90 00 02 00 06 00 2e 00 90 00 02 00 06 00 2e 00 90 00 02 00 06 00 2e 00 90 00 02 00 3c 00 2e 00 74 00 78 00 74 00 } 		$a_00_2 = {63 00 6d 00 64 00 20 00 2f 00 63 00 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}