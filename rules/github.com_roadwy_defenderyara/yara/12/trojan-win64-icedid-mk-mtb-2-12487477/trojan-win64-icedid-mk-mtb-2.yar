rule Trojan_Win64_Icedid_MK_MTB_2{
	meta:
		description = "Trojan:Win64/Icedid.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 04 24 48 8b 4c 24 08 eb 21 48 ff c0 48 89 44 24 08 eb c4 eb ce 48 8b 44 24 30 48 89 04 24 eb 27 48 8b 44 24 40 48 ff c8 eb c4 8a 09 88 08 eb 23 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}