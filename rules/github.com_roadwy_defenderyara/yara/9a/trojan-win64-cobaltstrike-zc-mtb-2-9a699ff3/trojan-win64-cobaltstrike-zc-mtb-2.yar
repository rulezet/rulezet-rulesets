rule Trojan_Win64_CobaltStrike_ZC_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.ZC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 c8 89 8c 24 ?? ?? ?? ?? 8a 54 34 ?? 0f b6 44 0c ?? 88 44 34 ?? 88 54 0c ?? 8b 94 24 ?? ?? ?? ?? 8b b4 24 ?? ?? ?? ?? 0f b6 4c 14 ?? 0f b6 44 34 ?? 03 c8 0f b6 c1 8b 4c 24 ?? 0f b6 44 04 ?? 30 04 19 41 89 4c 24 ?? 3b cf 72 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}