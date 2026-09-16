rule Trojan_Win32_SusRegSvr_MK_2{
	meta:
		description = "Trojan:Win32/SusRegSvr.MK,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {72 00 65 00 67 00 73 00 76 00 72 00 33 00 32 00 2e 00 65 00 78 00 65 00 20 00 2f 00 75 00 20 00 2f 00 73 00 } 		$a_00_1 = {70 00 68 00 6f 00 6e 00 65 00 68 00 6f 00 6d 00 65 00 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}