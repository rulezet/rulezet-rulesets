rule Backdoor_Win64_Bedep_A{
	meta:
		description = "Backdoor:Win64/Bedep.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 89 4c 24 08 48 89 54 24 10 4c 89 44 24 18 48 89 5c 24 20 48 8d 4c 24 08 55 56 57 41 54 41 55 41 56 41 57 e8 00 00 00 00 5a 48 83 ec 20 e8 fd 21 00 00 48 83 c4 58 48 33 c0 c3 e8 00 00 00 00 5e 48 81 ee 40 00 00 00 48 8b f9 48 8d 41 5a b9 1c 00 00 00 fc f3 48 a5 ff e0 48 8b f2 49 8b c8 49 8b f9 48 c1 e9 03 f3 48 a5 4c 8b 7c 24 28 48 8b 5c 24 30 4c 8b 4c 24 38 48 83 ec 28 48 8b ca 48 33 d2 49 c7 c0 00 80 00 00 41 ff d1 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}