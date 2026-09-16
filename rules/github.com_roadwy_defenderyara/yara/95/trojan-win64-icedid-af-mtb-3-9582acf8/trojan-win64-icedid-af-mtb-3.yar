rule Trojan_Win64_IcedID_AF_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.AF!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 63 04 24 48 8b 4c 24 20 0f b6 04 01 89 44 24 04 48 63 0c 24 33 d2 48 8b c1 48 f7 74 24 40 48 8b c2 48 8b 4c 24 38 0f b6 04 01 8b 4c 24 04 33 c8 8b c1 48 63 0c 24 48 8b 54 24 28 88 04 0a } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}