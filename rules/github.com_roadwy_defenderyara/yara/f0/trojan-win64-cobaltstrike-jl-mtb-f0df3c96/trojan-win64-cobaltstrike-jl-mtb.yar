rule Trojan_Win64_CobaltStrike_JL_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.JL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 c2 83 e2 ?? 0f b6 14 17 32 14 03 41 88 54 05 ?? 48 83 c0 ?? 49 39 c6 75 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}