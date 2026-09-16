rule Trojan_Win64_IcedID_MW_MTB_4{
	meta:
		description = "Trojan:Win64/IcedID.MW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b 44 24 40 48 89 44 24 10 eb ?? 48 89 44 24 40 48 83 7c 24 10 00 76 ?? eb ?? 48 8b 44 24 30 48 83 c4 28 eb ?? 4c 89 44 24 18 48 89 54 24 10 eb ?? 8a 09 88 08 eb } 		$a_01_1 = {4a 6e 61 73 64 68 62 6a 61 73 64 73 } 	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}