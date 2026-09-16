rule Trojan_Win32_LummaStealer_Z_MTB_22{
	meta:
		description = "Trojan:Win32/LummaStealer.Z!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 5c 51 3a 1d ab d9 02 2b 28 3b 82 87 c3 08 c6 2e f4 5a b9 27 fd 1e 8e 28 6f 1f f5 17 06 f3 44 2f 35 77 ca 2a 48 ef b6 05 d8 59 22 61 3e ed e6 12 8c 2b d8 77 29 90 12 ac 0f 49 1c 8b dc fd 84 e4 44 f7 08 0c 1b fb 25 5b cc 8b a6 59 d7 77 70 2f b7 1f 6e 5b a0 94 0a 72 4c 37 a5 71 24 a8 23 70 fb 9a cd 3c 1a 37 22 59 1b d8 42 0f f7 2a ca dd a6 e5 0f 8e a5 c5 a4 6c e6 ec 01 fa 0b 49 63 69 aa bd 85 f5 d8 83 5b bb 42 0e 6a 7a 0e d1 0d cc d9 94 85 7a 8a 89 7d 5f e9 b1 99 f9 41 0f 48 d8 5e 24 5c a9 } 		$a_01_1 = {03 87 85 a2 e9 e5 c9 b6 13 5b 6c d0 2f da 86 22 fc 0b 5e 2a e7 1d 7c 1e bb 5c 5f 29 c3 46 3e 82 a3 6c 59 78 cf 57 91 5e 8a 76 33 db b7 7c df 50 d3 80 f6 4a 63 a7 d5 bf 7c 3a 78 b8 42 8c 21 83 61 9f e2 63 66 99 6e fb 5e b2 9e ac ca 96 42 f2 19 aa 79 07 7d d4 43 34 a1 1f 73 3f 82 d3 bd c9 93 34 ca a8 19 71 e0 ca a9 06 c0 5b 9b ae bb c1 69 f4 8a 1b ed 7c d6 01 31 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}