rule Trojan_Win32_Allegato_MA_MTB_2{
	meta:
		description = "Trojan:Win32/Allegato.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 04 00 00 "
		
	strings :
		$a_01_0 = {da d5 d5 9a dd 51 18 dc 4c d9 9d b4 df 1e 83 75 3b a7 ea 24 54 00 ff 68 59 04 0b 0d cc ca ba 24 99 80 9d a8 e7 50 95 87 23 02 c9 c5 b8 ca 38 d2 } 		$a_01_1 = {0b 8a d8 7d 71 a9 ee 48 c2 26 36 cf c9 7b 79 19 75 7d 0c b1 d9 2b 16 c8 ee 84 ee 4c 58 ed 67 93 75 cf 96 8b a0 5e f1 d6 af c6 26 47 ae ff 94 bb } 		$a_01_2 = {23 f0 1b da 4d 8c 3c 8a d6 ee ec d3 c4 e9 2c 9a 71 6c 71 95 b2 37 a0 71 b7 a7 6a 52 ce 3f 57 d8 0b 77 c8 47 91 d5 9b e5 c3 14 97 46 7c 44 d5 ee 56 b1 b5 07 1d fb b5 8c e4 71 dc ba 60 b6 a2 d0 } 		$a_01_3 = {e0 00 8e 81 0b 01 02 19 00 e8 05 00 00 7c 0e 00 00 00 00 00 38 95 05 00 00 10 00 00 00 00 06 00 00 00 40 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*3) >=18
 
}