rule Trojan_Win32_VBInject_MA_MTB_2{
	meta:
		description = "Trojan:Win32/VBInject.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_01_0 = {be 9b a0 72 68 3b a4 72 dc 9b a0 72 b7 70 a2 72 a0 25 a1 72 59 b2 a0 72 f7 e0 a0 72 e2 6f a2 72 b9 7d a2 72 74 9b a0 72 fd a0 94 72 61 b2 a0 72 87 9b a0 72 85 9a a0 72 df 47 a2 72 db 7d a3 72 26 7e a2 72 d1 97 a1 72 e9 8f a2 72 5d d0 a3 72 } 		$a_01_1 = {ff 25 30 10 40 00 ff 25 2c 10 40 00 ff 25 14 10 40 00 ff 25 00 10 40 00 ff 25 08 10 40 00 ff 25 04 10 40 00 ff 25 4c 10 40 00 ff 25 58 10 40 } 		$a_01_2 = {5a 6f 6d 62 69 65 5f 47 65 74 54 79 70 65 49 6e 66 6f } 		$a_01_3 = {79 00 79 00 4c 00 57 00 55 00 4f 00 6a 00 45 00 6e 00 63 00 70 00 56 00 67 00 57 00 67 00 6c 00 51 00 4b 00 70 00 6a 00 64 00 41 00 55 00 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=12
 
}