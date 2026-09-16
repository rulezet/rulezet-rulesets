rule Trojan_Win32_AsyncRAT_SB{
	meta:
		description = "Trojan:Win32/AsyncRAT.SB,SIGNATURE_TYPE_PEHSTR_EXT,ffffff97 00 ffffff97 00 06 00 00 "
		
	strings :
		$a_01_0 = {bf eb 1e 56 fb cd 97 3b b2 19 02 24 30 a5 78 43 00 3d 56 44 d2 1e 62 b9 d4 f1 80 e7 e6 c3 39 41 } 		$a_01_1 = {00 00 00 0d 53 00 48 00 41 00 32 00 35 00 36 00 00 } 		$a_01_2 = {09 50 00 6f 00 6e 00 67 00 00 } 		$a_80_3 = {70 61 73 74 65 62 69 6e } 		$a_80_4 = {70 6f 6e 67 } 		$a_80_5 = {53 74 75 62 2e 65 78 65 } 	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*50+(#a_01_2  & 1)*50+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=151
 
}