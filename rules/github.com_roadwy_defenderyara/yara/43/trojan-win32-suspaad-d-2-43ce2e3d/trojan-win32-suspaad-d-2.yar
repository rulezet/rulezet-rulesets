rule Trojan_Win32_SuspAAD_D_2{
	meta:
		description = "Trojan:Win32/SuspAAD.D,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {52 65 63 6f 6e 65 72 61 74 6f 72 2e 65 78 65 } 		$a_80_1 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}