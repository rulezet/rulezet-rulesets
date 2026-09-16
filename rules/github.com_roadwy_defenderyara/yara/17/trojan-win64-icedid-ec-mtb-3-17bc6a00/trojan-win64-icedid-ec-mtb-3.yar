rule Trojan_Win64_IcedID_EC_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 89 4c 24 20 4c 89 44 24 18 eb 64 b8 09 00 00 00 83 c0 03 eb 23 83 c0 1c 66 89 44 24 50 eb 0f c7 44 24 44 00 00 00 00 b8 01 00 00 00 eb 28 } 	condition:
		((#a_01_0  & 1)*8) >=8
 
}