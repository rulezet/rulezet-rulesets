rule Trojan_Win32_LummaStealer_Z_MTB_23{
	meta:
		description = "Trojan:Win32/LummaStealer.Z!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {7e 51 92 9b 7b 01 b1 5a b9 b5 da e8 09 a9 1a fd 78 b8 da 5d 35 72 cb 27 d2 e8 } 		$a_01_1 = {fc 06 93 24 ae 01 21 d2 28 2a ab 86 13 bd 37 48 f9 a8 ce 94 ff 03 b1 21 bf d3 f5 f5 54 5e c5 6e 27 20 7d 1b f9 fb 26 f4 d0 f3 02 76 57 09 83 c6 84 c0 21 ee 6b ef b8 b2 7a 02 54 75 af d8 73 0f 3f 4c c3 54 e0 ee d9 75 31 e1 ab bc 9e 45 10 0b 0c bf b8 f9 f4 f3 56 73 8e 76 2e a5 18 ba ce f8 ad 9b 0d 03 73 9b a9 e1 b3 e2 5e 7c b3 ca fd 7f 59 31 aa f3 27 06 ab 25 7d 9e 3f dc 03 7d 85 ba 9f 35 80 cd b1 7f 19 a9 39 ff 9c 3e 5b d3 41 e4 fc 65 a2 81 fd 6b d3 7d 94 1f 57 05 60 a9 b6 f1 57 09 76 2e c0 c0 57 ef b6 0a e9 21 d2 45 62 ff ae 50 3f 3d 07 49 e7 34 5f ab 9c 51 cb 1d 33 7b a1 ef bc 5b eb 14 97 42 2f 33 b4 56 ad e0 f3 17 e0 5e 6f 15 8c 54 3e 20 54 f2 ea c1 98 6d 64 } 		$a_01_2 = {e6 93 0f 32 8a 62 79 64 3f af 6a 4f 55 34 cf d2 aa 0a 05 a1 d2 b7 1f 29 bb 1f 1b be 5a 4a 29 f8 8e f9 46 71 74 71 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}