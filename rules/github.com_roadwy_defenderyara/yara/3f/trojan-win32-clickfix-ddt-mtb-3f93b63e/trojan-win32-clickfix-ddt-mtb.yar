rule Trojan_Win32_ClickFix_DDT_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DDT!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } 		$a_00_1 = {69 00 65 00 78 00 28 00 28 00 67 00 65 00 74 00 2d 00 63 00 6c 00 69 00 70 00 62 00 6f 00 61 00 72 00 64 00 20 00 2d 00 72 00 61 00 77 00 29 00 2e 00 73 00 75 00 62 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}