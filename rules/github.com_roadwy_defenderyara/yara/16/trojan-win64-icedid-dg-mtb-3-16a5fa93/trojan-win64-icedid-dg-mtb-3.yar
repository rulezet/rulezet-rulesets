rule Trojan_Win64_IcedID_DG_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {65 48 8b 04 25 60 00 00 00 48 89 84 24 90 00 00 00 48 8b 84 24 90 00 00 00 48 8b 40 18 48 89 84 24 80 00 00 00 48 c7 44 24 40 00 00 00 00 48 c7 44 24 38 00 00 00 00 b8 08 00 00 00 48 6b c0 01 48 8b 8c 24 80 00 00 00 48 8b 44 01 08 48 89 44 24 50 eb 17 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}