rule Trojan_Win32_ClickFix_DDI_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DDI!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,6f 00 6f 00 03 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } 		$a_00_1 = {7c 00 4f 00 75 00 74 00 2d 00 53 00 74 00 72 00 69 00 6e 00 67 00 } 		$a_00_2 = {63 00 75 00 72 00 6c 00 } 	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*10+(#a_00_2  & 1)*1) >=111
 
}