rule Backdoor_Win32_Zloader_ST__6{
	meta:
		description = "Backdoor:Win32/Zloader.ST!!Zloader.ST,SIGNATURE_TYPE_ARHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {45 78 70 65 72 69 65 6e 63 65 2e 64 6c 6c 00 53 61 77 70 61 79 } 		$a_01_1 = {c7 05 78 47 04 01 34 01 00 00 2b cb 39 3d 90 47 04 01 72 24 8d 34 76 81 c6 9e 2f 01 00 8b c6 } 	condition:
		((#a_80_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}