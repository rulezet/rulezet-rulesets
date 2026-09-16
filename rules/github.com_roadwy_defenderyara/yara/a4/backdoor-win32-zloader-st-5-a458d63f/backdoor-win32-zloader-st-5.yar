rule Backdoor_Win32_Zloader_ST__5{
	meta:
		description = "Backdoor:Win32/Zloader.ST!!Zloader.ST,SIGNATURE_TYPE_ARHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {77 68 65 65 6c 2e 64 6c 6c 00 43 6f 6e 73 6f 6e 61 6e 74 71 75 6f 74 69 65 6e 74 } 		$a_01_1 = {69 ff dc d7 00 00 8b d0 2b d7 f6 2d 23 e0 08 10 a2 23 e0 08 10 } 	condition:
		((#a_80_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}