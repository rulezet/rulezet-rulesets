rule Backdoor_Win32_PcClient_3{
	meta:
		description = "Backdoor:Win32/PcClient,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {5c 73 76 63 68 6f 73 74 2e 65 78 65 00 00 00 00 44 6f 53 65 72 76 69 63 65 00 00 00 75 70 64 61 74 65 65 76 65 6e 74 00 25 73 3d 00 2e 73 79 73 00 00 00 00 64 72 69 76 65 72 73 5c 00 } 		$a_01_1 = {ea 8f 57 79 4f 17 af 21 c4 da d9 24 f0 13 06 b7 df 18 66 14 23 e0 6b 58 29 91 5e a4 d8 7e ed 19 96 2c c8 a7 06 e8 80 33 e2 d9 18 e7 1d 1b e0 7e 91 21 99 67 66 b0 44 01 93 0c d6 f0 32 87 90 56 7c f9 05 20 a2 7e e9 c7 6a f8 16 f3 5a 33 c8 57 e0 75 4e 91 cf 77 b8 97 14 ca 12 c8 fe d9 48 f2 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}