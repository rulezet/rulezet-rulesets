rule Ransom_Win32_Dopplepaymer_A_5{
	meta:
		description = "Ransom:Win32/Dopplepaymer.A,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {66 b8 17 a1 8b 4c 24 10 89 4c 24 14 8b 4c 24 14 8b 54 24 04 8a 1c 0a 66 8b 74 24 0e 88 5c 24 1b 66 69 7c 24 2e 63 f2 8b 0c 24 03 4c 24 14 66 89 7c 24 2e 89 4c 24 1c 66 39 f0 76 15 c7 44 24 10 00 00 00 00 eb ba 8b 04 24 8d 65 f4 5e 5f 5b 5d c3 8b 44 24 30 8b 4c 24 28 83 f1 ff 35 a9 86 ef 37 89 4c 24 28 8b 4c 24 1c 8a 54 24 1b 88 11 03 44 24 14 89 44 24 10 8b 4c 24 08 39 c8 74 c7 e9 7c ff } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}