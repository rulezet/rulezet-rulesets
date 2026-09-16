rule Backdoor_Win32_Poison_G{
	meta:
		description = "Backdoor:Win32/Poison.G,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {e8 1b 00 00 00 43 4f 4e 4e 45 43 54 20 25 73 3a 25 69 20 48 54 54 50 2f 31 2e 30 0d 0a 0d 0a 00 5a 8d bd 34 fb ff ff } 		$a_01_1 = {c5 08 00 00 ff 96 89 00 00 00 3d b7 00 00 00 75 04 c9 c2 04 00 56 8d 86 6b 09 00 00 50 8d 86 45 01 00 00 50 ff 96 fd 00 00 00 e8 07 00 00 00 77 73 32 5f 33 32 00 58 50 ff 96 9d 00 00 00 89 86 c3 0a 00 00 e8 3a 00 00 00 e1 60 b4 8e 01 00 d1 41 29 7c 15 00 1e bb ec 65 19 00 0c 58 ed ea 1d } 		$a_03_2 = {bd 30 fa ff ff 63 6b 73 3d 75 13 c7 85 30 fa ff ff 74 74 ?? 3d c6 86 ef 0a 00 00 02 eb 11 c7 85 30 fa ff ff 63 6b 73 3d c6 86 ef 0a 00 00 01 ff } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=12
 
}