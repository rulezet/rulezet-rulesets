rule Trojan_Win64_CobaltStrike_CI_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 0f b6 03 03 c3 0f b6 c0 0f b6 8c 04 ?? ?? 00 00 80 c1 03 41 30 0a 49 ff c2 48 83 ef 01 75 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}