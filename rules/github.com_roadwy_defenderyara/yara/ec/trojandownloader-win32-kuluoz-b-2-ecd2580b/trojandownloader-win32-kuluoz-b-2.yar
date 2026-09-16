rule TrojanDownloader_Win32_Kuluoz_B_2{
	meta:
		description = "TrojanDownloader:Win32/Kuluoz.B,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 05 00 00 "
		
	strings :
		$a_03_0 = {8b 51 24 03 55 ?? 89 55 ?? c6 45 ?? 57 c6 45 ?? 6f c6 45 ?? 72 c6 45 ?? 6b c6 45 ?? 00 } 		$a_03_1 = {8b 42 24 03 85 ?? ?? ff ff 89 85 ?? ?? ff ff c6 85 ?? ?? ff ff 57 c6 85 ?? ?? ff ff 6f c6 85 ?? ?? ff ff 72 c6 85 ?? ?? ff ff 6b c6 85 ?? ?? ff ff 00 } 		$a_03_2 = {c6 42 01 68 8b 45 ?? 03 85 ?? ?? ff ff 8b 4d ?? 89 48 02 8b 55 90 1b 00 03 95 90 1b 01 ff ff c6 42 06 c3 } 		$a_03_3 = {c6 40 01 68 8b 4d ?? 03 8d ?? ?? ff ff 8b 55 ?? 89 51 02 8b 45 ?? 03 85 ?? ?? ff ff c6 40 06 c3 } 		$a_01_4 = {2e 70 68 70 3f 72 3d 67 61 74 65 26 69 64 3d } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*10) >=11
 
}