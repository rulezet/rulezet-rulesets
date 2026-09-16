rule Trojan_Win32_NetworkSniffing_ZPB{
	meta:
		description = "Trojan:Win32/NetworkSniffing.ZPB,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {70 00 6b 00 74 00 6d 00 6f 00 6e 00 } 		$a_00_1 = {66 00 69 00 6c 00 74 00 65 00 72 00 20 00 61 00 64 00 64 00 20 00 2d 00 70 00 20 00 34 00 34 00 35 00 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}