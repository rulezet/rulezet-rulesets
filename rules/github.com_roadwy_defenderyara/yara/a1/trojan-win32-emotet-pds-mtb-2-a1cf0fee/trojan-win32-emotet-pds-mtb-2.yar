rule Trojan_Win32_Emotet_PDS_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.PDS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_00_0 = {8a 5c 04 0c 30 5c 3c 10 30 5c 3c 14 8b c6 83 e0 03 83 c6 06 8a 54 04 0c 30 54 3c 11 30 54 3c 15 } 		$a_02_1 = {2b c8 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 81 c2 a4 2b d1 01 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 45 ec 8b 0d ?? ?? ?? ?? 89 88 90 09 06 00 8b 0d } 		$a_00_2 = {8b 45 f0 03 45 e8 8d 0c 17 33 c1 81 c7 47 86 c8 61 33 45 e0 2b d8 8b 45 d8 83 ee 01 75 } 		$a_00_3 = {0f b6 5d 01 8b cf c1 e1 1c c1 f9 1f 81 e2 64 10 b7 1d 33 c2 81 e1 32 88 db 0e 33 c1 8b cf 8b d7 } 	condition:
		((#a_00_0  & 1)*2+(#a_02_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2) >=2
 
}