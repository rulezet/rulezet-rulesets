rule TrojanSpy_Win32_Embed_A_2{
	meta:
		description = "TrojanSpy:Win32/Embed.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {f3 a5 8d 48 02 b8 ab aa aa aa f7 e1 d1 ea a4 8d 04 52 89 45 f0 } 		$a_01_1 = {6a 04 50 56 c7 44 24 30 d4 c3 b2 a1 ff d7 } 		$a_01_2 = {68 88 13 00 00 ff d6 8d 4c 24 08 6a 00 51 ff d7 85 c0 74 ec 68 10 27 00 00 } 		$a_01_3 = {48 74 74 70 5f 64 6c 6c 2e 64 6c 6c 00 } 		$a_01_4 = {50 6c 61 79 57 6f 72 6b 00 } 		$a_01_5 = {57 69 6e 73 33 32 00 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}