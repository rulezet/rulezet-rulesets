rule Trojan_Win32_ClickFix_IIO_MTB_2{
	meta:
		description = "Trojan:Win32/ClickFix.IIO!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {46 00 6f 00 72 00 45 00 61 00 63 00 68 00 2d 00 4f 00 62 00 6a 00 65 00 63 00 74 00 7b 00 5b 00 63 00 68 00 61 00 72 00 5d 00 24 00 5f 00 } 		$a_00_1 = {2e 00 47 00 65 00 74 00 53 00 74 00 72 00 69 00 6e 00 67 00 } 		$a_00_2 = {68 00 69 00 64 00 64 00 65 00 6e 00 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}