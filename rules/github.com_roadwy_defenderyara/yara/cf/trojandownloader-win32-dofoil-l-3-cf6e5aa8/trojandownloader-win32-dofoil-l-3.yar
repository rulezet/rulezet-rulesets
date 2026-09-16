rule TrojanDownloader_Win32_Dofoil_L_3{
	meta:
		description = "TrojanDownloader:Win32/Dofoil.L,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {c7 03 07 00 01 00 } 		$a_01_1 = {89 83 b0 00 00 00 } 		$a_01_2 = {8a 06 32 c2 88 07 46 47 49 83 f9 00 75 f2 } 		$a_01_3 = {68 56 71 64 4f 8b 03 50 e8 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=3
 
}