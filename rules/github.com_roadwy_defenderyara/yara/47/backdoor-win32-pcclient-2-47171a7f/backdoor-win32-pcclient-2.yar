rule Backdoor_Win32_PcClient_2{
	meta:
		description = "Backdoor:Win32/PcClient,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {5c 73 76 63 68 6f 73 74 2e 65 78 65 00 00 00 00 44 6f 53 65 72 76 69 63 65 00 00 00 75 70 64 61 74 65 65 76 65 6e 74 00 25 73 3d 00 2e 73 79 73 00 00 00 00 64 72 69 76 65 72 73 5c 00 } 		$a_01_1 = {81 3e 46 a0 1f 26 5a 95 1e 7a 4e 02 64 10 64 fa 1f 36 ba 0a 90 cf 8d d1 61 1a 72 9a a2 6f 98 1f 7c a4 a3 31 79 63 ab ca a0 49 1a 93 06 a1 07 c8 20 08 0e 62 3b ea 15 27 74 e2 52 d9 84 7c 4b c4 6e 1f ba 01 9e fa 20 80 46 63 41 ba 50 99 35 9e 05 19 41 9b 9a 01 4e 37 2f e8 e0 04 9a ba ab d5 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}