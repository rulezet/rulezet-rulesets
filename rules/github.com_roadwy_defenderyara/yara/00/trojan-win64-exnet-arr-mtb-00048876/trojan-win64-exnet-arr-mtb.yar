rule Trojan_Win64_Exnet_ARR_MTB{
	meta:
		description = "Trojan:Win64/Exnet.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 44 24 0c 30 44 0c 0d 41 83 f9 } 		$a_03_1 = {c6 44 24 5f 00 50 33 c0 0f 9b c0 52 33 d0 c1 e2 ?? 92 5a 0b c1 } 	condition:
		((#a_01_0  & 1)*12+(#a_03_1  & 1)*8) >=20
 
}