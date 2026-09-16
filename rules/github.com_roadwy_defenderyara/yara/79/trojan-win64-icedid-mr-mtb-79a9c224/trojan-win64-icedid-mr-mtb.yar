rule Trojan_Win64_IcedID_MR_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 44 24 28 48 89 44 24 08 eb 31 48 8b 44 24 20 48 89 04 24 eb e9 88 08 48 8b 04 24 eb a9 48 8b 44 24 08 48 ff c0 eb a8 48 8b 4c 24 08 8a 09 eb e5 48 8b 44 24 20 48 83 c4 18 eb } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}