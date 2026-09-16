rule Trojan_Win32_FileFix_HHI_MTB_2{
	meta:
		description = "Trojan:Win32/FileFix.HHI!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {53 00 74 00 61 00 72 00 74 00 2d 00 42 00 69 00 74 00 73 00 74 00 72 00 61 00 6e 00 73 00 66 00 65 00 72 00 } 		$a_00_1 = {20 00 20 00 23 00 20 00 } 		$a_00_2 = {68 00 74 00 74 00 70 00 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}