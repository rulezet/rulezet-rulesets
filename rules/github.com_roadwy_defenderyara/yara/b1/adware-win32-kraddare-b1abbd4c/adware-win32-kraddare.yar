rule Adware_Win32_Kraddare{
	meta:
		description = "Adware:Win32/Kraddare,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_80_0 = {77 77 77 2e 6d 75 75 6b 2e 63 6f 2e 6b 72 } 		$a_80_1 = {77 69 6e 64 6f 77 73 74 61 62 2e 65 78 65 } 		$a_80_2 = {77 69 6e 64 6f 77 73 74 61 62 2e 70 68 70 } 	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=4
 
}