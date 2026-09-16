rule Trojan_Win64_Poolinject_PGP_MTB_2{
	meta:
		description = "Trojan:Win64/Poolinject.PGP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {28 d1 30 c1 31 c0 28 c8 88 44 24 06 8b 4c 24 08 48 8b 54 24 18 44 8a 44 24 0f 8a 44 24 06 44 30 c0 4c 63 c1 42 88 04 02 83 c1 01 83 f9 1e 89 4c 24 28 88 44 24 2f 0f 85 } 		$a_01_1 = {28 d1 30 c1 31 c0 28 c8 88 44 24 06 8b 4c 24 08 48 8b 54 24 18 44 8a 44 24 0f 8a 44 24 06 44 30 c0 4c 63 c1 42 88 04 02 83 c1 01 83 f9 08 89 4c 24 28 88 44 24 2f 0f 85 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}