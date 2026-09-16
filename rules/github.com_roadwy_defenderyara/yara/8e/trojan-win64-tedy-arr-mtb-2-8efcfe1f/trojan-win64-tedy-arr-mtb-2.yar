rule Trojan_Win64_Tedy_ARR_MTB_2{
	meta:
		description = "Trojan:Win64/Tedy.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {4c 0f 47 44 24 ?? 4c 8b 4c 24 ?? 49 ff c1 4c 89 7c 24 ?? 48 8b d0 48 8b ce } 		$a_81_1 = {7a 65 74 72 65 78 6f 61 2d 63 72 65 61 74 65 } 	condition:
		((#a_03_0  & 1)*8+(#a_81_1  & 1)*2) >=10
 
}