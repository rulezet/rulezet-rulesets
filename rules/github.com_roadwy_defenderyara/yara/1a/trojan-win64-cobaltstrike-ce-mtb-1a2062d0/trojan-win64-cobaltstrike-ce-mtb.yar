rule Trojan_Win64_CobaltStrike_CE_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 63 c2 0f b6 44 04 ?? 43 32 44 11 } 	condition:
		((#a_03_0  & 1)*3) >=3
 
}