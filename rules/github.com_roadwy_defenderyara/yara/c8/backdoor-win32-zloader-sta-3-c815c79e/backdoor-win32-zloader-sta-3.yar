rule Backdoor_Win32_Zloader_STA_3{
	meta:
		description = "Backdoor:Win32/Zloader.STA,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {77 65 61 72 2e 64 6c 6c 00 4d 65 65 69 67 68 74 } 		$a_01_1 = {c7 05 78 47 04 01 11 01 00 00 8d 51 b8 03 d6 69 c2 31 b4 00 00 89 15 08 48 04 01 2b c1 } 	condition:
		((#a_80_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}