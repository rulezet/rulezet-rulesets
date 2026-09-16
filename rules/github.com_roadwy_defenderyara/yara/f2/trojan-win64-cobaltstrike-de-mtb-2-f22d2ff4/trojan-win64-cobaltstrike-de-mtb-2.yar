rule Trojan_Win64_CobaltStrike_DE_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b 4c 24 28 0f b6 04 01 89 44 24 30 48 63 4c 24 20 33 d2 48 8b c1 b9 ?? ?? ?? ?? 48 f7 f1 48 8b c2 8b 4c 24 30 33 4c 84 40 8b c1 48 63 4c 24 20 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}