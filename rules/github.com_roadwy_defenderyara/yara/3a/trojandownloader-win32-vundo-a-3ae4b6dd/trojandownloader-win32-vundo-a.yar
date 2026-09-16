rule TrojanDownloader_Win32_Vundo_A{
	meta:
		description = "TrojanDownloader:Win32/Vundo.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {47 65 74 4c 61 73 74 41 63 74 69 76 65 50 6f 70 75 70 00 } 		$a_02_1 = {8b 48 28 85 c9 74 14 a1 ?? ?? ?? 10 6a 00 03 c8 6a 03 50 89 0d ?? ?? ?? 10 ff d1 c3 } 		$a_02_2 = {8a 00 88 45 b0 0f b6 45 ac 0f b6 4d b0 33 c1 8b 0d ?? ?? ?? 10 03 0d ?? ?? ?? 10 88 01 e9 } 	condition:
		((#a_01_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=2
 
}