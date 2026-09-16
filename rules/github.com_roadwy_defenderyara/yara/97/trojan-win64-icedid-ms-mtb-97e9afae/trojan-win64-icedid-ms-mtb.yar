rule Trojan_Win64_IcedID_MS_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {66 c7 40 18 2f 6b 48 8b f1 eb d3 48 89 70 20 57 eb 15 0f b6 c1 0f 46 d0 eb 00 42 88 54 04 20 49 ff c0 e9 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}