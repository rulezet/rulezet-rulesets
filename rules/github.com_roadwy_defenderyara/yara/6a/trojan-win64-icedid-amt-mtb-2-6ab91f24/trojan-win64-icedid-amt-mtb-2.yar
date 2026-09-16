rule Trojan_Win64_IcedId_AMT_MTB_2{
	meta:
		description = "Trojan:Win64/IcedId.AMT!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 81 ec 38 01 00 00 bb 10 80 27 00 48 8d 74 24 20 89 1e 89 5c 24 28 f2 0f 2a 44 24 28 48 8d 7c 24 30 f2 0f 11 07 } 		$a_01_1 = {48 81 ec 58 01 00 00 be b7 c1 27 00 89 74 24 2c 89 74 24 28 f2 0f 2a 44 24 28 f2 0f 11 44 24 30 89 74 24 2c 89 74 24 28 0f 57 c0 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}