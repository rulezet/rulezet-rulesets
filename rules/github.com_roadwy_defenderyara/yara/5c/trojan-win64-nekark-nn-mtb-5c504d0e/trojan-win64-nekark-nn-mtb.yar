rule Trojan_Win64_Nekark_NN_MTB{
	meta:
		description = "Trojan:Win64/Nekark.NN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {c7 44 24 0c 02 00 00 00 c7 44 24 08 00 00 00 00 c7 44 24 04 2c 80 40 00 c7 04 24 01 00 00 80 e8 9f 56 00 00 83 ec 14 89 45 f4 83 7d f4 00 } 		$a_01_1 = {8b 45 f0 89 54 24 14 8b 55 08 89 54 24 10 c7 44 24 0c 01 00 00 00 c7 44 24 08 00 00 00 00 c7 44 24 04 5a 80 40 00 89 04 24 e8 5f 56 00 00 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}