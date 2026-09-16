rule Trojan_Win32_Shimming_B{
	meta:
		description = "Trojan:Win32/Shimming.B,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_80_0 = {73 64 62 69 6e 73 74 20 2d 71 } 		$a_80_1 = {61 69 5f 73 68 69 6d 5f 74 65 73 74 2e 73 64 62 } 		$a_80_2 = {73 64 62 69 6e 73 74 20 2d 71 20 2d 75 } 	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*-10) >=4
 
}