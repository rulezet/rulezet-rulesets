rule Trojan_Win32_ClickFix_DDG_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DDG!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {29 00 2e 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 7e 00 68 00 74 00 74 00 } 		$a_00_1 = {c3 00 8e 00 45 00 58 00 20 00 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}