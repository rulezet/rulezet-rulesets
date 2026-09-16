rule Backdoor_Win32_Zloader_ST_{
	meta:
		description = "Backdoor:Win32/Zloader.ST!!Zloader.ST,SIGNATURE_TYPE_ARHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {43 61 72 72 79 2e 64 6c 6c 00 41 62 6c 65 } 		$a_01_1 = {81 c1 08 16 00 00 02 d8 8d 42 55 03 c1 88 1d be c9 18 01 69 c0 20 64 00 00 } 	condition:
		((#a_80_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}