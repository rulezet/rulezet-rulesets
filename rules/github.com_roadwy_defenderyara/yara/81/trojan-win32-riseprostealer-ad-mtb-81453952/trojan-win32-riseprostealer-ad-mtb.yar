rule Trojan_Win32_RiseProStealer_AD_MTB{
	meta:
		description = "Trojan:Win32/RiseProStealer.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {31 01 8b 0c 24 83 c4 04 52 50 } 		$a_01_1 = {01 d0 01 18 58 5a 55 52 } 		$a_01_2 = {89 14 24 ba 83 41 d9 71 c1 e2 03 c1 ea 02 81 c2 fb 7c 4d dc 29 d1 5a } 		$a_81_3 = {41 79 33 49 6e 66 6f 2e 65 78 65 } 		$a_01_4 = {25 75 73 65 72 61 70 70 64 61 74 61 25 5c 52 65 73 74 61 72 74 41 70 70 2e 65 78 65 } 		$a_01_5 = {5c 2e 5c 47 6c 6f 62 61 6c 5c 6f 72 65 61 6e 73 33 32 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_81_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}