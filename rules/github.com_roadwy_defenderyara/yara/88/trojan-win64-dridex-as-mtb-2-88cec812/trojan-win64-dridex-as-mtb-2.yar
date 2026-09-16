rule Trojan_Win64_Dridex_AS_MTB_2{
	meta:
		description = "Trojan:Win64/Dridex.AS!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b c2 b9 40 00 00 00 83 e0 3f 2b c8 33 c0 48 d3 c8 b9 20 00 00 00 48 33 c2 f3 48 ab 48 8b 7c 24 08 b0 01 c3 } 		$a_01_1 = {41 8b c2 b9 40 00 00 00 83 e0 3f 2b c8 48 d3 cf 49 33 fa 4b 87 bc f7 00 ca 09 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}