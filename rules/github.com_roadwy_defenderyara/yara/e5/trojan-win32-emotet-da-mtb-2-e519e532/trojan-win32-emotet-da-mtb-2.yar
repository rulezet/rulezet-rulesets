rule Trojan_Win32_Emotet_DA_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 89 e5 56 50 8a 45 14 8b 4d 10 8b 55 0c 8b 75 08 b4 ?? c6 45 fb ?? 2a 65 fb 30 e0 02 04 0a 88 04 0e 83 c4 04 5e 5d c3 } 		$a_03_1 = {8a 1c 11 0f b6 fb 8b 4d d0 01 f9 89 c8 89 55 c8 99 f7 fe 8b 4d e0 8a 3c 11 8b 75 f0 81 f6 ?? ?? ?? ?? 89 55 c4 8b 55 c8 88 3c 11 8b 55 c4 88 1c 11 8b 4d f0 8b 55 e0 8b 5d c8 0f b6 14 1a 01 fa 81 c1 ?? ?? ?? ?? 21 ca 8b 4d e0 8a 0c 11 8b 55 e8 8b 7d cc 32 0c 3a 8b 55 e4 88 0c 3a } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}