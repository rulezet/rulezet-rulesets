rule Ransom_Win32_Gulcrypt_A_2{
	meta:
		description = "Ransom:Win32/Gulcrypt.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {0a ed e0 e6 ec e8 f2 e5 20 ea ed ee ef ea f3 20 43 72 65 61 74 65 20 72 61 6e 64 6f 6d 20 61 64 64 72 65 73 73 2e 20 c2 f1 e5 2c 20 e2 fb 20 ec } 		$a_01_1 = {ea ed ee ef ea f3 20 53 65 6e 64 20 4d 65 73 73 61 67 65 0d 0a 28 ef ee f1 eb e0 f2 fc 20 f1 ee } 		$a_03_2 = {21 21 d4 e0 e9 eb fb 20 e7 e0 f8 e8 f4 f0 ee e2 e0 ed fb [0-05] 2e 74 78 74 00 } 		$a_03_3 = {b9 19 00 00 00 bb 01 00 00 00 d3 e3 23 d8 74 2d 80 c1 41 88 0d ?? ?? 40 00 80 e9 41 c7 05 ?? ?? 40 00 3a 5c 2a 2e c6 05 ?? ?? 40 00 2a c6 05 ?? ?? 40 00 00 50 51 e8 ?? ?? ff ff 59 58 49 7d c5 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*5+(#a_03_3  & 1)*5) >=6
 
}