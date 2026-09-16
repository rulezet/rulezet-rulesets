rule Trojan_Win32_Emotet_AD_3{
	meta:
		description = "Trojan:Win32/Emotet.AD,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a 11 2a 44 24 4b 8a 64 24 2b 30 c4 00 e2 8b 4c 24 0c 8b 74 24 14 88 14 31 } 		$a_01_1 = {8a 75 cb 80 c6 73 8b 45 e4 8b 4d cc 02 34 08 28 d6 8b 75 e0 88 34 0e 83 c1 3e 8b 7d e8 39 f9 8b 5d c4 89 5d d0 89 4d d4 72 ae } 		$a_03_2 = {8b 45 e4 8b 4d f4 81 c1 7a 04 8e b7 89 c2 21 ca 8b 4d e8 89 0c 24 8b 75 ec 89 74 24 04 89 44 24 08 0f b6 14 15 ?? ?? ?? ?? 89 54 24 0c 89 45 e0 e8 d2 0b 00 00 8b 45 e0 83 c0 01 8b 4d f0 39 c8 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}