rule TrojanDownloader_Win32_Renos{
	meta:
		description = "TrojanDownloader:Win32/Renos,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {32 07 c1 c0 07 0f af c0 69 c0 44 33 22 11 c1 c8 0f 69 c0 11 33 22 44 c1 c8 05 0f af c0 69 c0 13 13 00 00 ae e2 da } 		$a_03_1 = {ff e0 8b d8 81 eb ?? ?? ?? ?? 8d bb ?? ?? ?? ?? b9 40 00 00 00 81 37 ?? ?? ?? ?? af e2 f7 e8 24 00 00 00 } 		$a_03_2 = {75 06 ff 80 b8 00 00 00 33 c0 c2 10 00 64 ff 35 00 00 00 00 64 89 25 00 00 00 00 cc 64 8f 05 00 00 00 00 5f 8b 3c 24 b9 ?? ?? ?? ?? 81 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}