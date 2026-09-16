rule Trojan_Win64_CobaltStrike_JV_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.JV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 c2 83 e2 ?? 41 8a 14 14 32 54 05 ?? 88 14 06 48 ff c0 eb } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}