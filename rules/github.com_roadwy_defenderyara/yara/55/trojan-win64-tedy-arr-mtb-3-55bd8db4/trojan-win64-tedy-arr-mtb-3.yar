rule Trojan_Win64_Tedy_ARR_MTB_3{
	meta:
		description = "Trojan:Win64/Tedy.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c7 ff c7 48 8d 49 ?? 83 e0 07 0f b6 04 10 30 41 ff 41 3b f9 72 } 		$a_81_1 = {33 41 44 30 35 35 37 35 2d 38 38 35 37 2d 34 38 35 30 2d 39 32 37 37 2d 31 31 42 38 35 42 44 42 38 45 30 39 } 	condition:
		((#a_03_0  & 1)*15+(#a_81_1  & 1)*5) >=20
 
}