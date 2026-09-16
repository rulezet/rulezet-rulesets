rule Trojan_Win32_ClickFix_FFL_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.FFL!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {69 00 65 00 78 00 20 00 28 00 69 00 72 00 6d 00 20 00 68 00 74 00 74 00 70 00 } 		$a_00_1 = {2e 00 69 00 6e 00 6b 00 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}