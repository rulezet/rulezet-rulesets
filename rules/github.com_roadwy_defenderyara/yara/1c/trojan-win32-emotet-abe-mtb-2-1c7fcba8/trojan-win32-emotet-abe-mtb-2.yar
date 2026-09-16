rule Trojan_Win32_Emotet_ABE_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.ABE!MTB,SIGNATURE_TYPE_PEHSTR,02 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {99 b9 fa 02 00 00 f7 f9 a1 c4 b0 04 10 0f af 05 c4 b0 04 10 2b d0 8b 0d b4 b0 04 10 0f af 0d b4 b0 04 10 03 15 c4 b0 04 10 03 ca 8b 15 c4 b0 04 10 0f af 15 c4 b0 04 10 2b ca a1 b4 b0 04 10 0f af 05 b4 b0 } 		$a_01_1 = {5e 41 6c 77 65 24 66 36 59 61 66 71 41 51 31 52 46 6c 37 63 64 46 37 4f 35 70 30 44 67 3f 76 49 26 74 } 		$a_01_2 = {d7 50 f9 8d 31 41 42 33 ae ef 35 9a d5 a6 78 7f 0e 4c 3e c2 be 42 cf bd d0 65 c9 3e 4a 2f 4a 62 e6 fa 76 65 e1 2d c6 47 47 51 ed 1a f1 47 9a f6 45 ea fe 27 5c 0d 33 a7 9f a9 6b f5 48 81 af e8 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}