rule Backdoor_Win32_Plugx_L_dha_2{
	meta:
		description = "Backdoor:Win32/Plugx.L!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_01_0 = {b9 58 56 00 00 8b d1 66 3b 10 74 07 6a 0f e9 7c 02 00 00 8b 70 3c 03 f0 39 0e 74 07 } 		$a_01_1 = {81 78 1c 18 00 1a 00 74 08 8b 00 85 c0 75 f1 } 		$a_01_2 = {0f b7 00 25 ff 0f 00 00 03 01 03 c7 89 45 ec 33 c0 89 45 f4 8b c7 99 8b f8 2b 7e 34 } 		$a_01_3 = {c1 ea 18 32 54 0e 04 8b 4d 08 c1 e9 10 32 d1 8b 4d 08 c1 e9 08 32 d1 32 55 08 88 14 37 } 		$a_01_4 = {8b 46 04 c6 00 e9 8b 46 04 88 58 01 8b 4e 04 8b c3 c1 e8 08 } 		$a_01_5 = {80 7c 38 14 a3 75 07 80 7c 38 19 e8 74 0f } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=3
 
}