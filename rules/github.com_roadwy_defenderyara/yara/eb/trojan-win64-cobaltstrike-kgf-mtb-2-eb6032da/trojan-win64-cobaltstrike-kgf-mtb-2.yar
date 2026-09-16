rule Trojan_Win64_Cobaltstrike_KGF_MTB_2{
	meta:
		description = "Trojan:Win64/Cobaltstrike.KGF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 89 ea 45 31 db 41 89 f2 41 c1 e2 ?? 49 01 da 31 c0 41 0f b6 0c 82 30 0c 02 48 83 c0 01 48 83 f8 04 75 } 		$a_03_1 = {48 83 c2 01 49 89 c2 c0 e8 04 83 e0 0f 41 83 e2 ?? 48 c1 e0 04 4c 01 e0 42 0f b6 04 10 88 42 ff 48 39 d1 75 } 	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*4) >=9
 
}