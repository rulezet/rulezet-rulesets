rule Trojan_Win64_CobaltStrike_PQ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.PQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b cb 44 38 6d ?? 74 ?? 45 85 c9 7e ?? 48 8d 95 ?? ?? ?? ?? 48 2b d3 45 8b c1 8a 04 0a 30 01 48 ff c1 49 83 e8 ?? 75 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}