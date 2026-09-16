rule Trojan_Win64_Exnet_ARR_MTB_2{
	meta:
		description = "Trojan:Win64/Exnet.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 4c 24 30 8b d0 81 f2 ?? ?? ?? ?? 83 c0 ?? 03 d1 89 54 24 30 } 		$a_03_1 = {0f be c9 48 8d 40 ?? 41 33 c8 44 69 c1 ?? ?? ?? ?? 0f b6 08 44 33 c2 } 	condition:
		((#a_03_0  & 1)*11+(#a_03_1  & 1)*9) >=20
 
}