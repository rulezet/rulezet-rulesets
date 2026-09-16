rule Trojan_Win32_Vidar_MA_MTB_5{
	meta:
		description = "Trojan:Win32/Vidar.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_01_0 = {26 77 9d 6e 61 8f cb b8 15 dc fc d3 47 0f 2e 62 1b 7d 6a bf 25 8d 84 f0 a9 f3 cb 82 15 70 13 2b } 		$a_01_1 = {16 a5 10 90 12 f3 c8 7d f6 0c 92 67 ff ff ff ff d9 bb d0 4d db da 77 45 e4 e9 e2 d4 b5 b6 c7 19 } 		$a_01_2 = {85 5c 6a 56 1c 88 8e b0 1e 6d e2 7c af 7f e5 5a 74 2a 70 7d 95 9b f0 7a 70 14 4c 8f 28 3e a3 60 ea 61 55 bb 9f f0 cf 5b 73 a5 95 e2 54 e5 5c 0f a4 fa a3 5a ea 21 b9 12 a5 50 04 13 cb 98 } 		$a_01_3 = {e0 00 02 01 0b 01 0a 00 00 d4 03 00 00 30 19 00 00 00 00 00 4f 06 25 } 		$a_01_4 = {2e 76 6d 70 30 } 		$a_01_5 = {2e 76 6d 70 32 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=10
 
}