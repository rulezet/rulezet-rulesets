rule Backdoor_Win32_PcClient_6{
	meta:
		description = "Backdoor:Win32/PcClient,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {5c 73 76 63 68 6f 73 74 2e 65 78 65 00 00 00 44 6f 53 65 72 76 69 63 65 00 00 00 6d 79 67 75 69 64 00 00 6d 79 70 61 72 65 6e 74 74 68 72 65 61 64 69 64 00 00 00 00 25 73 3d 00 2e 73 79 73 00 00 00 00 64 72 69 76 65 72 73 5c 00 } 		$a_01_1 = {3e 89 81 03 84 41 b5 54 7d 4e c0 a0 d0 16 21 1b f6 ce 83 f6 35 21 28 e0 4b c0 67 ba 16 65 09 56 4f 54 27 66 19 10 68 ac 16 61 0f 18 20 17 30 61 78 08 82 01 8e 61 08 10 e0 ea a7 cb 72 d0 9e 14 06 3c e1 aa 9d 76 ec 5e 1e ed 6a 4e f6 62 44 27 3a a6 0f a8 19 3e 1b 24 44 13 a3 8c 09 01 ea 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}