rule Trojan_Win32_Emotet_K_3{
	meta:
		description = "Trojan:Win32/Emotet.K,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 07 00 00 "
		
	strings :
		$a_01_0 = {74 5e c1 ef 02 33 c0 53 33 db 8d 14 be 8b fa 2b fe 83 c7 03 c1 ef 02 3b f2 0f 47 f8 85 ff 74 37 } 		$a_01_1 = {8d 49 08 33 55 08 8d 76 04 0f b6 c2 43 66 89 41 f8 8b c2 c1 e8 08 0f b6 c0 66 89 41 fa c1 ea 10 0f b6 c2 66 89 41 fc c1 ea 08 0f b6 c2 66 89 41 fe 3b df 72 c9 } 		$a_03_2 = {8d 44 24 0c ba 0c 00 00 00 50 68 ?? ?? ?? ?? b9 ?? ?? ?? ?? e8 ?? ?? ff ff 8b ?? 24 14 83 c4 08 ?? ff 15 ?? ?? ?? ?? 85 c0 74 1b 68 } 		$a_03_3 = {8d 45 f8 ba 0c 00 00 00 50 68 ?? ?? ?? ?? b9 ?? ?? ?? ?? e8 ?? ?? ff ff 8b 75 f8 68 } 		$a_03_4 = {83 c0 04 c7 85 cc fb ff ff 04 01 00 00 89 85 c4 fb ff ff 57 c7 00 00 00 00 00 8d 85 dc fb ff ff 50 68 ?? ?? ?? ?? e8 be db ff ff 8d 85 d0 fb ff ff ba 28 00 00 00 50 68 } 		$a_03_5 = {8d 45 f8 ba 04 00 00 00 50 68 ?? ?? ?? ?? b9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 75 f8 8d ?? ?? ?? ?? ff 68 } 		$a_03_6 = {75 2a 8d 04 5d 02 00 00 00 50 8d ?? ?? ?? ?? ff 50 6a 01 6a 00 68 ?? ?? ?? ?? ff 75 f4 ff 15 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1+(#a_03_6  & 1)*1) >=4
 
}