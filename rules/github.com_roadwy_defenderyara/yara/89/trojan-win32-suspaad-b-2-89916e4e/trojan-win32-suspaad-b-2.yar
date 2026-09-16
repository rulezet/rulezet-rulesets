rule Trojan_Win32_SuspAAD_B_2{
	meta:
		description = "Trojan:Win32/SuspAAD.B,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {6e 6c 74 65 73 74 20 } 		$a_80_1 = {2f 64 6f 6d 61 69 6e 5f 74 72 75 73 74 73 } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}