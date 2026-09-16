rule Trojan_Win32_Zenpak_P_MTB_2{
	meta:
		description = "Trojan:Win32/Zenpak.P!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 "
		
	strings :
		$a_03_0 = {8b 75 cc 32 0c 32 8b 55 ?? 88 0c 32 } 		$a_01_1 = {8b 3f 8b 00 0f b7 12 31 fa } 		$a_01_2 = {c6 85 d4 fe ff ff 56 c6 85 d5 fe ff ff 69 c6 85 d6 fe ff ff 72 c6 85 d7 fe ff ff 74 c6 85 d8 fe ff ff 75 c6 85 d9 fe ff ff 61 c6 85 da fe ff ff 6c c6 85 db fe ff ff 41 c6 85 dc fe ff ff 6c c6 85 dd fe ff ff 6c c6 85 de fe ff ff 6f c6 85 df fe ff ff 63 } 		$a_01_3 = {c6 45 d4 56 c6 45 d5 69 c6 45 d6 72 c6 45 d7 74 c6 45 d8 75 c6 45 d9 61 c6 45 da 6c c6 45 db 41 c6 45 dc 6c c6 45 dd 6c c6 45 de 6f c6 45 df 63 } 		$a_01_4 = {c6 45 94 6b c6 45 95 65 c6 45 96 72 c6 45 97 6e c6 45 98 65 c6 45 99 6c c6 45 9a 33 c6 45 9b 32 c6 45 9c 2e c6 45 9d 64 c6 45 9e 6c c6 45 9f 6c } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=2
 
}