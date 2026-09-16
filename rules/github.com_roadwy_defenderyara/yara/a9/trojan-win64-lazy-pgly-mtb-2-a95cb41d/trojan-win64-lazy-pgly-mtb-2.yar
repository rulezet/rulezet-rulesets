rule Trojan_Win64_Lazy_PGLY_MTB_2{
	meta:
		description = "Trojan:Win64/Lazy.PGLY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {19 4a 0a a4 03 8e b2 56 bc 45 bf 9f 87 da e4 eb 9a af 1e 52 4c 45 c1 05 ef 39 e4 d1 f7 fa 6a ea 96 5e cb 83 d5 24 93 ef 89 17 4d 61 fe 92 4f 72 25 22 1f c2 60 26 1d f7 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}