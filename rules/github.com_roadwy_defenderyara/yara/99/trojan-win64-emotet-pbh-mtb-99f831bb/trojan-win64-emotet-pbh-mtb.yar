rule Trojan_Win64_Emotet_PBH_MTB{
	meta:
		description = "Trojan:Win64/Emotet.PBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 f9 8b c2 48 98 48 8b [0-06] 0f b6 04 01 8b 4c 24 ?? 33 c8 8b c1 8b 4c 24 ?? 8b 54 24 ?? 2b d1 8b ca 03 4c 24 ?? 48 63 c9 48 8b 54 24 ?? 88 04 0a eb } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}