rule Trojan_Win64_IcedID_ML_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.ML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 89 04 24 48 8b 44 24 08 eb 00 48 ff c0 48 89 44 24 08 eb d4 eb 47 48 89 4c 24 08 48 83 ec 28 eb 31 48 8b 44 24 40 48 ff c8 eb 40 8a 09 88 08 eb } 		$a_01_1 = {48 89 44 24 08 48 8b 44 24 30 eb 46 48 ff c0 48 89 04 24 eb 00 48 8b 44 24 08 48 ff c0 eb e1 48 89 4c 24 08 48 83 ec 18 eb 00 48 8b 44 24 20 48 89 04 24 eb 29 88 08 48 8b 04 24 eb } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=5
 
}