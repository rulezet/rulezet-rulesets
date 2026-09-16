rule Trojan_Win64_CobaltStrike_CF_MTB_4{
	meta:
		description = "Trojan:Win64/CobaltStrike.CF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {74 63 65 74 48 8b d3 c7 ?? 24 44 6f 72 50 6c 41 b8 [0-04] c7 44 24 ?? 61 75 74 72 66 c7 44 24 ?? 69 56 0f b6 44 14 ?? 42 0f b6 4c 04 ?? 42 88 44 04 ?? 49 ff c8 88 4c 14 ?? 48 ff c2 49 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}