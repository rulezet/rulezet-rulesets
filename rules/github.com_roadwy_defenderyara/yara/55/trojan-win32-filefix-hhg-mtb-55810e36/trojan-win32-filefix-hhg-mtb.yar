rule Trojan_Win32_FileFix_HHG_MTB{
	meta:
		description = "Trojan:Win32/FileFix.HHG!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {3b 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-50] 24 00 } 		$a_00_1 = {2d 00 6f 00 75 00 74 00 66 00 69 00 6c 00 65 00 } 	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}