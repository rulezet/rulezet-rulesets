rule Trojan_Win32_Farfli_CV_MTB_2{
	meta:
		description = "Trojan:Win32/Farfli.CV!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 50 6a eb 01 40 27 80 38 e8 30 04 c6 cc 1a 48 16 5c f6 f7 7c 40 01 07 0f b6 1e 88 18 46 90 34 3e 29 f4 47 25 ec c9 0c 44 24 1c 61 cc 75 60 } 		$a_01_1 = {cd 07 ad c1 c8 b0 35 87 36 2a 74 56 75 f2 } 		$a_01_2 = {67 42 a2 e4 28 22 69 32 4d 14 1b 44 e8 8d 35 9d 17 19 0b 43 dc 34 9c 7f 03 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}