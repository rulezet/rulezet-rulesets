rule Adware_Win32_Kraddare_2{
	meta:
		description = "Adware:Win32/Kraddare,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_80_0 = {77 77 77 2e 6d 75 75 6b 2e 63 6f 2e 6b 72 2f 61 70 70 2f 77 69 6e 64 6f 77 73 74 61 62 } 		$a_80_1 = {77 69 6e 64 6f 77 73 74 61 62 2e 70 68 70 } 		$a_80_2 = {4e 65 74 58 74 72 65 6d 65 } 	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=4
 
}