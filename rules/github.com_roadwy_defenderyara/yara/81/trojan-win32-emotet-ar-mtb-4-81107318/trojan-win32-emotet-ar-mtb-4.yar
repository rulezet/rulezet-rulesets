rule Trojan_Win32_Emotet_AR_MTB_4{
	meta:
		description = "Trojan:Win32/Emotet.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f0 0f b6 14 38 8a 1f 03 55 fc 0f b6 c3 03 c2 33 d2 f7 f1 8d 04 32 89 55 fc 8a 10 88 18 88 17 47 ff 4d f4 } 		$a_03_1 = {0f b6 14 2b 8a 03 03 54 24 10 0f b6 c0 03 c2 33 d2 f7 f1 8a 03 47 43 8a 0c 32 88 04 32 88 4b ff 8b 0d ?? ?? ?? ?? 3b f9 89 54 24 10 } 		$a_03_2 = {8a 0c 37 8b da 8a 04 33 88 0c 33 88 04 37 0f b6 14 33 0f b6 c0 03 c2 33 d2 f7 35 ?? ?? ?? ?? 89 54 24 14 } 		$a_81_3 = {54 64 66 64 67 66 73 51 72 63 67 78 67 63 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*2+(#a_81_3  & 1)*2) >=3
 
}