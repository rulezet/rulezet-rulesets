rule Backdoor_Win32_PcClient_4{
	meta:
		description = "Backdoor:Win32/PcClient,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {5c 73 76 63 68 6f 73 74 2e 65 78 65 00 44 6f 53 65 72 76 69 63 65 00 00 00 6d 79 67 75 69 64 00 00 6d 79 70 61 72 65 6e 74 74 68 72 65 61 64 69 64 00 00 00 00 25 73 3d 00 2e 73 79 73 00 00 00 00 64 72 69 76 65 72 73 5c 00 } 		$a_01_1 = {81 31 2a e2 cf 3f 0c e2 0a e8 70 00 3e e9 b5 10 0a 94 88 3a e0 a8 8c 25 31 89 10 09 1e 2d 25 9c 74 26 24 6a d4 20 00 4c 61 11 34 e1 40 4c a8 f6 49 db c4 64 11 e9 b8 c2 4a aa 09 80 5b 81 60 6f 69 c1 c0 0e b0 21 3c 9e 8c 0f 18 e1 1c 49 49 ec 40 a1 1e 30 41 a4 45 20 c0 5a 28 10 05 66 b9 15 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}