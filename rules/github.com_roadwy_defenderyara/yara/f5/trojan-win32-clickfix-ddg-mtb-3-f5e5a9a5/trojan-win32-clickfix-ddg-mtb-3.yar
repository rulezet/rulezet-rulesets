rule Trojan_Win32_ClickFix_DDG_MTB_3{
	meta:
		description = "Trojan:Win32/ClickFix.DDG!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,ffffffa1 00 ffffffa1 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 20 00 2d 00 43 00 } 		$a_00_1 = {7b 00 26 00 20 00 28 00 64 00 69 00 72 00 20 00 5c 00 57 00 2a 00 5c 00 2a 00 33 00 32 00 5c 00 63 00 3f 00 3f 00 6c 00 2e 00 65 00 2a 00 29 00 2e 00 4e 00 61 00 6d 00 65 00 } 		$a_00_2 = {7c 00 20 00 69 00 65 00 78 00 } 		$a_00_3 = {68 00 74 00 74 00 70 00 } 	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*50+(#a_00_2  & 1)*10+(#a_00_3  & 1)*1) >=161
 
}