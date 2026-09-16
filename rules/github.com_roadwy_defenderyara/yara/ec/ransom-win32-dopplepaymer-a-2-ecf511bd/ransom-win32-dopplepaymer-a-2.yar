rule Ransom_Win32_Dopplepaymer_A_2{
	meta:
		description = "Ransom:Win32/Dopplepaymer.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b dd 32 c0 8b cb fe c0 d1 e9 8b d1 81 f2 20 83 b8 ed f6 c3 01 8b da 0f 44 d9 3c 08 7c e6 89 1c ae 45 81 fd 00 01 00 00 7c d6 } 		$a_01_1 = {0f b6 33 4a 33 f0 43 81 e6 ff 00 00 00 c1 e8 08 33 04 b1 83 fa ff 75 e8 } 		$a_01_2 = {0f b6 44 24 08 c1 e0 08 0f b6 4a 11 03 c1 c6 42 10 01 80 3a 00 74 16 8b 7a 08 8b 4a 04 66 89 04 79 ff 42 08 85 c0 75 11 33 c0 40 eb 0e } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}