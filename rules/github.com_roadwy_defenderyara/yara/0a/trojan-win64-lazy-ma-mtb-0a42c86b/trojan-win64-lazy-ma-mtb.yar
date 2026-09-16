rule Trojan_Win64_Lazy_MA_MTB{
	meta:
		description = "Trojan:Win64/Lazy.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 03 00 00 "
		
	strings :
		$a_01_0 = {e9 80 00 00 00 4d 8b cb eb 02 25 ed 4c 3b db eb 03 3d 0e c3 4c 0f 47 cb eb 03 68 cd 6a 4d 2b d9 eb 02 c0 5b e9 9b 00 00 00 eb 02 } 		$a_01_1 = {4d 5a b1 4a 92 35 da 32 ad b4 4c d2 d9 6e c6 3b e6 5b 19 27 36 d2 a1 85 ae b5 1d 64 f5 36 b9 4d e3 3a 14 3f 1b 6b ad 6a 5f 9c 8c 49 8b e2 0e ee } 		$a_01_2 = {53 48 47 65 74 44 69 73 6b 46 72 65 65 53 70 61 63 65 41 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*2) >=22
 
}