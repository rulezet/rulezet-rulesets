rule Trojan_Win64_Latrodectus_PH_MTB_2{
	meta:
		description = "Trojan:Win64/Latrodectus.PH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b c1 b9 06 00 00 00 90 13 83 c1 02 48 f7 f1 90 13 48 8b c2 48 8b 4c 24 ?? 90 13 0f b6 44 01 ?? 8b 8c 24 ?? 00 00 00 90 13 33 c8 8b c1 90 13 48 63 4c 24 ?? 48 8b 54 24 ?? 90 13 88 04 0a 90 13 8b 44 24 ?? 90 13 ff c0 89 44 24 ?? e9 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}