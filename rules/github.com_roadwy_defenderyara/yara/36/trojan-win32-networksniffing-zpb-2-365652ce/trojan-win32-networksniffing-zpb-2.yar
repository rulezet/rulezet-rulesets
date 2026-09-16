rule Trojan_Win32_NetworkSniffing_ZPB_2{
	meta:
		description = "Trojan:Win32/NetworkSniffing.ZPB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {70 00 6b 00 74 00 6d 00 6f 00 6e 00 } 		$a_00_1 = {73 00 74 00 61 00 72 00 74 00 20 00 2d 00 2d 00 65 00 74 00 77 00 20 00 } 		$a_00_2 = {20 00 2d 00 66 00 20 00 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}