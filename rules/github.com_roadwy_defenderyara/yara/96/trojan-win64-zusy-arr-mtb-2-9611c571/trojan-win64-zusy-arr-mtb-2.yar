rule Trojan_Win64_Zusy_ARR_MTB_2{
	meta:
		description = "Trojan:Win64/Zusy.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 44 24 60 32 c8 88 8c 15 ?? ?? ?? ?? 48 ff c2 48 83 fa } 		$a_01_1 = {0f b6 54 24 30 0f b6 4c 24 31 32 d1 88 54 04 3c 48 ff c0 48 83 f8 } 	condition:
		((#a_03_0  & 1)*11+(#a_01_1  & 1)*9) >=20
 
}