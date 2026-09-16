rule Trojan_Win32_Dridex_ES_MTB{
	meta:
		description = "Trojan:Win32/Dridex.ES!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_00_0 = {5b 3b 33 82 92 73 e9 64 96 e7 49 5f 0d 43 b7 7c c5 f1 82 ec 73 7b 53 11 3d dc 53 3b e2 1e e3 06 a8 90 58 af 44 b4 91 df 31 39 8a d2 46 15 35 1b } 		$a_00_1 = {4c 1d af 38 79 87 0b f7 58 b4 be 0e 37 de fd 54 } 		$a_80_2 = {4c 64 72 47 65 74 50 72 6f 63 65 64 75 72 65 41 } 	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*5+(#a_80_2  & 1)*1) >=11
 
}