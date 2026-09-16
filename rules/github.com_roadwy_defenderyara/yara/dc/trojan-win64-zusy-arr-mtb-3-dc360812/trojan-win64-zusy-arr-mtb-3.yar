rule Trojan_Win64_Zusy_ARR_MTB_3{
	meta:
		description = "Trojan:Win64/Zusy.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {66 0f 46 c8 41 c1 e0 ?? 66 41 89 09 4d 8d 49 ?? 49 ff ca 75 } 		$a_01_1 = {0f b6 c8 41 8b 00 d3 c8 41 33 c3 2b c2 41 89 00 4d 8d 40 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*15) >=20
 
}