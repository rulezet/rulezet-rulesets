rule Trojan_Win32_Emotet_AU{
	meta:
		description = "Trojan:Win32/Emotet.AU,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 16 8d 49 08 33 55 08 8d 76 04 0f b6 c2 47 66 89 41 f8 8b c2 c1 e8 08 0f b6 c0 66 89 41 fa c1 ea 10 0f b6 c2 66 89 41 fc c1 ea 08 0f b6 c2 66 89 41 fe 3b fb 72 c9 } 		$a_03_1 = {8b 16 8d 49 04 [0-06] 8d 76 04 88 51 fc 8b c2 c1 e8 08 47 c1 ea 10 88 41 fd 88 51 fe c1 ea 08 88 51 ff 3b fb 72 } 		$a_01_2 = {66 83 38 5c 74 0b 83 c0 02 66 83 38 00 75 f1 eb 06 33 c9 66 89 48 02 6a 00 } 		$a_03_3 = {83 c4 04 33 c9 39 4d 14 8b f0 0f 45 ce 6a 00 68 00 c3 4c 84 6a 00 6a 00 6a 00 [0-03] 51 57 ff 15 ?? ?? ?? ?? 56 6a 00 8b f8 ff 15 } 	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=6
 
}