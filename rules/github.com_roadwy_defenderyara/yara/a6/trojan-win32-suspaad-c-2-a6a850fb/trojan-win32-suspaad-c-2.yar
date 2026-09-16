rule Trojan_Win32_SuspAAD_C_2{
	meta:
		description = "Trojan:Win32/SuspAAD.C,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_80_0 = {77 68 6f 61 6d 69 2e 65 78 65 } 		$a_80_1 = {2f 61 6c 6c } 		$a_80_2 = {2f 67 72 6f 75 70 73 } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=2
 
}