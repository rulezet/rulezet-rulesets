rule Trojan_Win32_ClickFix_DDQ_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DDQ!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,6e 00 6e 00 02 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } 		$a_00_1 = {29 00 7c 00 25 00 7b 00 5b 00 63 00 68 00 61 00 72 00 5d 00 24 00 5f 00 7d 00 29 00 2d 00 6a 00 6f 00 69 00 6e 00 } 	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*10) >=110
 
}