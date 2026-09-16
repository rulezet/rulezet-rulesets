rule Backdoor_Win32_Zloader_STA_4{
	meta:
		description = "Backdoor:Win32/Zloader.STA,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {63 72 6f 70 2e 64 6c 6c 00 42 61 6c 6c 62 72 6f 77 6e } 		$a_01_1 = {ba 95 25 00 00 41 2b d1 8b c2 c1 e0 06 2b c2 03 c1 89 15 98 e0 08 10 a3 08 e0 08 10 } 	condition:
		((#a_80_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}