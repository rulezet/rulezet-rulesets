rule TrojanSpy_Win32_Gamker_A_3{
	meta:
		description = "TrojanSpy:Win32/Gamker.A,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 07 00 00 "
		
	strings :
		$a_01_0 = {c6 85 cf fe ff ff 66 c6 85 d0 fe ff ff 74 c6 85 d1 fe ff ff 53 c6 85 d2 fe ff ff 53 c6 85 d3 fe ff ff 35 c6 85 d4 fe ff ff 35 c6 85 d5 fe ff ff 31 c6 85 d6 fe ff ff 31 c6 85 d7 fe ff ff 47 c6 85 d8 fe ff ff 61 c6 85 d9 fe ff ff 74 c6 85 da fe ff ff 65 } 		$a_01_1 = {c6 85 d7 fe ff ff 66 c6 85 d8 fe ff ff 74 c6 85 d9 fe ff ff 53 c6 85 da fe ff ff 53 c6 85 db fe ff ff 35 c6 85 dc fe ff ff 35 c6 85 dd fe ff ff 31 c6 85 de fe ff ff 31 c6 85 df fe ff ff 47 c6 85 e0 fe ff ff 61 c6 85 e1 fe ff ff 74 c6 85 e2 fe ff ff 65 } 		$a_03_2 = {4d 69 63 72 c7 45 ?? 6f 73 6f 66 c7 45 ?? 74 53 53 35 c7 45 ?? 35 31 31 47 c7 45 ?? 61 74 65 00 } 		$a_01_3 = {65 79 75 69 6f 61 00 00 71 77 72 74 70 73 64 66 67 68 6a 6b 6c 7a 78 63 76 62 6e 6d 5f 00 } 		$a_01_4 = {33 d2 4f f7 f7 8a 54 15 d4 8b 45 fc 8b 4d 08 88 14 08 80 fa 5f 0f 84 05 ff ff ff 40 89 45 fc 3b 45 0c 0f 8c e8 fd ff ff } 		$a_03_5 = {eb 05 8b ff 8b 4d f4 0f b6 0c 31 88 4d fe 8a 88 00 01 00 00 0f b6 f9 0f b6 14 07 03 f8 88 55 0b 8a 90 ?? 00 00 02 55 0b } 		$a_01_6 = {83 f9 18 72 5d 8b 1e 81 fb 41 50 33 32 75 53 8b 5e 04 83 fb 18 72 4b 29 d9 72 47 39 4e 08 77 42 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_03_2  & 1)*10+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1+(#a_01_6  & 1)*1) >=13
 
}