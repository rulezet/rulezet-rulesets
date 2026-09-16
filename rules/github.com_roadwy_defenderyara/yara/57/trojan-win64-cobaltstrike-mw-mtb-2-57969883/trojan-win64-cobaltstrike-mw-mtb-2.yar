rule Trojan_Win64_CobaltStrike_MW_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.MW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b 44 24 60 48 63 48 04 f6 44 0c 70 06 75 48 33 c9 ff 15 ?? ?? ?? ?? 41 b9 40 00 00 00 41 b8 00 30 00 00 48 8b d6 33 c9 ff 15 ?? ?? ?? ?? 48 8b d8 4c 8b c6 48 8b d5 48 8b c8 e8 ?? ?? ?? ?? 45 33 c0 48 8b d3 33 c9 ff 15 ?? ?? ?? ?? 48 8b c8 ff 15 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}