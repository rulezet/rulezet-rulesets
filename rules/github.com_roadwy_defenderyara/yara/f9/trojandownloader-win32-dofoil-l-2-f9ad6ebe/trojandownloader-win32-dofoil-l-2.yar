rule TrojanDownloader_Win32_Dofoil_L_2{
	meta:
		description = "TrojanDownloader:Win32/Dofoil.L,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {3f 63 6d 64 3d 67 65 74 6c 6f 61 64 26 } 		$a_01_1 = {eb 08 e8 09 00 00 00 89 46 fc ad 85 c0 75 f3 c3 56 89 c2 8b 45 3c 8b 7c 28 78 01 ef } 	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}