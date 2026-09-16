rule Backdoor_Win32_PcClient_5{
	meta:
		description = "Backdoor:Win32/PcClient,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {5c 73 76 63 68 6f 73 74 2e 65 78 65 00 00 44 6f 53 65 72 76 69 63 65 00 00 00 6d 79 67 75 69 64 00 00 6d 79 70 61 72 65 6e 74 74 68 72 65 61 64 69 64 00 00 00 00 25 73 3d 00 2e 73 79 73 00 00 00 00 64 72 69 76 65 72 73 5c 00 } 		$a_01_1 = {81 a3 2b 0d 5f f1 50 ef 1a 3a a2 57 00 3b 40 85 99 03 32 88 18 85 1e be c4 57 d1 86 1d d4 80 c9 d0 41 0c 98 8d 95 30 58 90 90 08 0d b8 ef 67 ad 40 02 6d c5 03 61 55 24 58 83 01 61 c0 12 3d 42 5f 8f 8c 81 ac b9 d5 b8 00 8b a4 d9 12 dd c1 b1 c7 0f 62 bc 44 0d f4 d0 6e 58 c3 52 58 43 17 a8 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}