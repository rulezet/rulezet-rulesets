rule Trojan_Win64_XWorm_DA_MTB{
	meta:
		description = "Trojan:Win64/XWorm.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b c2 83 e0 1f 0f b6 44 18 ?? 30 04 16 48 ff c2 49 3b d0 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}