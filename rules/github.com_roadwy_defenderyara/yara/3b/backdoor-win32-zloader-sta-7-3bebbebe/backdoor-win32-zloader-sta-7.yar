rule Backdoor_Win32_Zloader_STA_7{
	meta:
		description = "Backdoor:Win32/Zloader.STA,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {48 6f 75 72 2e 64 6c 6c 00 4e 61 74 69 6f 6e } 		$a_01_1 = {69 c2 a1 d7 00 00 89 54 24 0c 2b c3 8a 3d 85 b9 18 01 8a 1d 83 b9 18 01 83 e8 07 80 ff 08 72 18 69 c8 a3 d7 00 00 } 	condition:
		((#a_80_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}