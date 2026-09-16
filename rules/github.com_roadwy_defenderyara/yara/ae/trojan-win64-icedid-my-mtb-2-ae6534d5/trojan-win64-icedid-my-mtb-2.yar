rule Trojan_Win64_IcedID_MY_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.MY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 09 88 08 eb ?? 48 8b 44 24 08 48 8b 4c 24 10 eb ?? 48 8b 44 24 30 48 89 44 24 08 eb ?? 8b 44 24 40 ff c8 eb ?? 48 ff c0 48 89 44 24 10 eb } 		$a_01_1 = {47 62 68 61 6a 61 73 64 61 73 } 	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}