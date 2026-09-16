rule Trojan_Win64_CobaltStrike_AJ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.AJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b c2 89 44 24 ?? 8b 04 24 48 8b 4c 24 ?? 0f b6 04 01 8b 4c 24 ?? 48 8b 54 24 ?? 0f b6 0c 0a 33 c1 8b 0c 24 48 8b 54 24 ?? 88 04 0a 8b 04 24 48 8b 4c 24 ?? 0f b6 04 01 03 44 24 ?? 8b 0c 24 48 8b 54 24 ?? 88 04 0a eb } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}