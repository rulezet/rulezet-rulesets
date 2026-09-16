rule TrojanDownloader_Win32_Dofoil_L{
	meta:
		description = "TrojanDownloader:Win32/Dofoil.L,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 03 50 e8 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 02 68 } 		$a_03_1 = {8b 44 24 0c 50 a1 ?? ?? ?? ?? 8b 00 ff d0 3d 03 01 00 00 75 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}