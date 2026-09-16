rule Trojan_Win64_CobaltStrike_CI_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.CI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 eb 8b cb ff c3 d1 fa 8b c2 c1 e8 ?? 03 d0 6b c2 ?? 2b c8 48 63 c1 42 0f b6 04 10 41 30 40 ?? 49 83 e9 ?? 75 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}