rule TrojanDropper_Win32_Sirefef_gen_B_5{
	meta:
		description = "TrojanDropper:Win32/Sirefef.gen!B,SIGNATURE_TYPE_ARHSTR_EXT,02 00 02 00 0a 00 00 "
		
	strings :
		$a_01_0 = {81 c1 5a 02 00 00 81 d2 10 54 00 00 33 c1 8b ce 33 ca } 		$a_01_1 = {8b 84 30 7c a2 e7 ff 8d 84 08 89 9e ff ff 8b 4d 08 03 c8 } 		$a_01_2 = {8b 45 e4 8b 4d e4 33 c7 c1 e8 02 f7 d1 c1 e1 1e 0b c1 89 45 ac } 		$a_01_3 = {8b 45 e8 8b 4d e8 33 c7 c1 e8 02 c1 e1 1e c1 e2 1e 0b c8 89 4d 98 8d 9d 64 ff ff ff c7 45 ec 05 00 00 00 ff 73 04 } 		$a_01_4 = {b9 6b 77 00 00 66 03 c1 0f b7 4d f4 0f af c1 66 89 45 f4 b8 3a 59 00 00 66 89 45 f8 } 		$a_01_5 = {8b 4d 14 0f ac c8 02 c1 e9 02 8b 4d 10 8b 55 14 33 c6 33 d2 0b c2 } 		$a_01_6 = {c1 e9 02 8b 4d d0 8b 55 d4 c1 e1 1e 8b 4d ec 33 c7 33 d2 0b c2 8a 0c 08 } 		$a_01_7 = {8b 45 08 c1 e1 1e 8b 4d 0c 0f ac c8 02 c1 e9 02 8b 4d 08 8b 55 0c 33 c6 33 d2 0b c2 03 c7 } 		$a_01_8 = {c1 e2 1e c1 e8 02 0b d0 8d 04 d5 78 00 00 00 8b 55 0c 8b 04 02 89 45 0c 8b 45 f0 8b 55 f4 0f ac d0 02 c1 ea 02 } 		$a_01_9 = {8b 00 8b 89 a4 01 00 00 8b 40 3c 8b 09 8d 44 01 28 8b 00 01 45 f8 8b 45 0c 89 45 0c 8b 45 f0 8b 4d f4 0f ac c8 02 c1 e9 02 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=2
 
}