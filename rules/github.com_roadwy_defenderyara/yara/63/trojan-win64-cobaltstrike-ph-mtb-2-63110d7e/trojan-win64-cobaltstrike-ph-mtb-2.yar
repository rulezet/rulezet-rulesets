rule Trojan_Win64_CobaltStrike_PH_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.PH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 63 44 24 ?? 48 8b 4c 24 ?? 0f b6 04 01 89 44 24 ?? 48 63 4c 24 ?? 33 d2 48 8b c1 b9 15 00 00 00 48 f7 f1 48 8b c2 8b 4c 24 ?? 33 8c 84 ?? ?? ?? ?? 8b c1 48 63 4c 24 ?? 48 8b 54 24 ?? 88 04 0a eb } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}