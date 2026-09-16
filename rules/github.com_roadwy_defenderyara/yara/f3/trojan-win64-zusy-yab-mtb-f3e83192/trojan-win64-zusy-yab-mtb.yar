rule Trojan_Win64_Zusy_YAB_MTB{
	meta:
		description = "Trojan:Win64/Zusy.YAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 c1 e0 02 48 2b c8 49 0f af cf 8a 44 0d ?? 43 32 04 0a 41 88 01 49 ff c1 41 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}