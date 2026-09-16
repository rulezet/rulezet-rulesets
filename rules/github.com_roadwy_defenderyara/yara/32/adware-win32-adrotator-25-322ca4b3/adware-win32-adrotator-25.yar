rule Adware_Win32_AdRotator_25{
	meta:
		description = "Adware:Win32/AdRotator,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {c7 44 24 24 7a c3 3f 19 c6 44 24 2c aa c6 44 24 2d 57 c6 44 24 2e 1a c6 44 24 2f cd c6 44 24 30 87 c6 44 24 31 c2 c6 44 24 32 6b c6 44 24 33 66 8b 10 8b 12 } 		$a_01_1 = {66 89 44 24 40 89 5c 24 48 c6 84 24 88 01 00 00 0e 8b 4c 24 40 8b 54 24 44 8b 7c 24 48 8b 6c 24 4c } 		$a_03_2 = {33 d1 8b 4e 08 88 54 24 08 0f b6 54 24 08 2b c8 8a 49 ?? 32 d1 8b 0e 88 14 08 } 		$a_03_3 = {66 33 14 01 03 c8 66 89 51 02 8b 4e 08 0f b7 (54|7c) 08 02 83 c0 04 83 f8 ?? 72 cf 33 c0 b9 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}