rule Trojan_Win64_Vidar_ARR_MTB{
	meta:
		description = "Trojan:Win64/Vidar.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {46 8a 1c 12 45 30 c3 46 88 1c 11 41 bb } 		$a_03_1 = {41 0f be 55 00 49 ff c5 85 d2 41 b8 ?? ?? ?? ?? 44 0f 44 c3 eb ?? 41 89 c8 41 c1 e0 ?? 01 d1 44 01 c1 41 b8 } 	condition:
		((#a_01_0  & 1)*15+(#a_03_1  & 1)*5) >=20
 
}