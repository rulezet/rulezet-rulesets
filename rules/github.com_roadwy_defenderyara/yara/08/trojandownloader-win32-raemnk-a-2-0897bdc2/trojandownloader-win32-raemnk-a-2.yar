rule TrojanDownloader_Win32_Raemnk_A_2{
	meta:
		description = "TrojanDownloader:Win32/Raemnk.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {c7 45 fc 01 00 00 00 c7 45 fc 02 00 00 00 6a ff e8 ?? ?? ?? ?? c7 45 fc 03 00 00 00 c7 45 a0 ?? ?? ?? ?? c7 45 98 08 00 00 00 8d 55 98 } 		$a_03_1 = {66 8b c8 66 2b 4d ?? 0f 80 ?? ?? 00 00 66 03 ce 0f 80 ?? ?? 00 00 0f bf c9 3b cb 7d ?? 6a 1e 59 66 2b c1 b9 ff 00 00 00 0f 80 ?? ?? 00 00 66 03 c6 0f 80 ?? ?? 00 00 66 2b 4d 90 1b 00 0f 80 ?? ?? 00 00 66 03 ce 0f 80 ?? ?? 00 00 66 03 c1 0f 80 ?? ?? 00 00 0f bf c8 } 		$a_03_2 = {66 8b c8 66 2b 4d ?? 0f 80 ?? ?? 00 00 66 03 ce 0f 80 ?? ?? 00 00 0f bf c9 3b cb 7d ?? b9 ff 00 00 00 6a 1e 66 8b d1 59 66 2b 55 90 1b 00 0f 80 ?? ?? 00 00 66 03 d6 0f 80 ?? ?? 00 00 66 2b c1 0f 80 ?? ?? 00 00 66 03 c6 0f 80 ?? ?? 00 00 66 03 d0 0f 80 ?? ?? 00 00 0f bf ca } 	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=11
 
}