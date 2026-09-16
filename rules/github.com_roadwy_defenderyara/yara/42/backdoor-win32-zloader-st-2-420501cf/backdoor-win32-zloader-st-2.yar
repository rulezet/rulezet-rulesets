rule Backdoor_Win32_Zloader_ST__2{
	meta:
		description = "Backdoor:Win32/Zloader.ST!!Zloader.ST,SIGNATURE_TYPE_ARHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {41 72 65 2e 64 6c 6c 00 53 68 65 65 74 70 6c 61 6e } 		$a_01_1 = {2a c2 83 c3 13 8a d0 69 f3 48 04 01 00 c0 e0 03 02 d0 c0 e2 03 80 c2 58 } 	condition:
		((#a_80_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}