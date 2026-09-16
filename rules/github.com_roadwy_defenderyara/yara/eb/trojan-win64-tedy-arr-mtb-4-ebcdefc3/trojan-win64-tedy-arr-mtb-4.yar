rule Trojan_Win64_Tedy_ARR_MTB_4{
	meta:
		description = "Trojan:Win64/Tedy.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 "
		
	strings :
		$a_03_0 = {4c 0f af f2 49 31 de c4 c3 fb f0 c5 ?? 48 0f af c2 4c 01 f7 } 		$a_03_1 = {41 8b 44 24 ?? 89 df 48 01 f7 83 c3 } 		$a_03_2 = {41 0f b7 4d 14 48 8d 04 0f 8b 54 0f ?? 39 da 77 } 	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*2+(#a_03_2  & 1)*8) >=20
 
}