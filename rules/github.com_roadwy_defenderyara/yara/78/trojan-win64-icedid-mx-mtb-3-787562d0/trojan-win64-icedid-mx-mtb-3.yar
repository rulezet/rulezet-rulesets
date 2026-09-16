rule Trojan_Win64_IcedID_MX_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b 44 24 30 48 83 c4 28 eb ?? 89 44 24 40 83 3c 24 00 7e ?? eb ?? 8b 44 24 40 89 04 24 eb ?? 48 8b 44 24 38 48 89 44 24 10 eb ?? 8a 09 88 08 eb } 		$a_01_1 = {54 6a 64 62 68 61 73 62 73 } 	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}