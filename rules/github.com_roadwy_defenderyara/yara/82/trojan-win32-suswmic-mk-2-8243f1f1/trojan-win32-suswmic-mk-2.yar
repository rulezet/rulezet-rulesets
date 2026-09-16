rule Trojan_Win32_SusWmIc_MK_2{
	meta:
		description = "Trojan:Win32/SusWmIc.MK,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {77 00 6d 00 69 00 63 00 20 00 2f 00 6e 00 6f 00 64 00 65 00 3a 00 6c 00 6f 00 63 00 61 00 6c 00 68 00 6f 00 73 00 74 00 20 00 2f 00 6e 00 61 00 6d 00 65 00 73 00 70 00 61 00 63 00 65 00 3a 00 } 		$a_00_1 = {2f 00 66 00 6f 00 72 00 6d 00 61 00 74 00 3a 00 6c 00 69 00 73 00 74 00 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}