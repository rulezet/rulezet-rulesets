rule Trojan_Win64_Tedy_PGT_MTB_2{
	meta:
		description = "Trojan:Win64/Tedy.PGT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 33 c4 48 89 84 24 a0 03 00 00 48 8b da 4c 8b f1 48 89 94 24 c0 00 00 00 45 33 ff 44 89 7c 24 30 0f 57 c0 0f 11 02 4c 89 7a 10 4c 89 7a 18 41 b8 0f 05 00 00 48 8d 15 ?? ?? ?? 00 48 8b cb } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}