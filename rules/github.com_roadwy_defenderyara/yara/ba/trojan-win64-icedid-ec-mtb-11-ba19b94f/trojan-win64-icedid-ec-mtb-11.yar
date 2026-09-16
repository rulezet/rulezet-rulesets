rule Trojan_Win64_IcedID_EC_MTB_11{
	meta:
		description = "Trojan:Win64/IcedID.EC!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 44 24 23 0f b6 c0 8a 4c 24 20 0f b6 c9 33 c8 8b c1 88 44 24 20 8a 44 24 23 fe c0 88 44 24 23 48 8b 44 24 38 8a 4c 24 20 88 08 48 8b 44 24 38 48 ff c0 48 89 44 24 38 8b 44 24 28 ff c8 89 44 24 28 } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}