rule Trojan_Win64_CobaltStrike_DZ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.DZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 c0 0f b6 4c 24 ?? 33 c1 0f b7 4c 24 ?? 48 8b 54 24 ?? 88 04 0a 90 13 0f b7 44 24 ?? 66 ff c0 66 89 44 24 ?? 0f b7 44 24 ?? 0f b7 4c 24 ?? 3b c1 7d } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}