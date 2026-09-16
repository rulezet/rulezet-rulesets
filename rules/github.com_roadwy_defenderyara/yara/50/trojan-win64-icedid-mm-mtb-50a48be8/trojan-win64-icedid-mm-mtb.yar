rule Trojan_Win64_IcedID_MM_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 89 04 24 48 8b 44 24 08 eb 3b 48 8b 44 24 40 48 ff c8 eb 61 48 8b 04 24 48 8b 4c 24 08 eb 00 8a 09 88 08 eb 00 48 8b 04 24 48 ff c0 eb } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}