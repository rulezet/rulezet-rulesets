rule Trojan_Win32_Ekstak_GAN_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.GAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_01_0 = {6b 64 00 00 c0 0a 00 0d 15 b6 76 72 25 64 00 00 d4 00 00 57 93 06 be 00 00 01 00 04 00 10 10 } 		$a_01_1 = {2a 01 00 00 00 0d 31 7c 00 7f 94 78 00 00 c0 0a 00 0d 15 b6 76 f3 4d 78 00 00 d4 00 00 } 		$a_01_2 = {00 d0 88 60 00 6e 59 5a 00 00 fa 0e 00 a6 b9 6a 79 61 49 58 00 00 } 		$a_01_3 = {2a 01 00 00 00 9a d7 5f 00 38 a8 59 00 00 fa 0e 00 a6 b9 6a 79 ea 97 57 00 00 0e } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10) >=10
 
}