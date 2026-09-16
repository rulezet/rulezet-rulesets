rule Trojan_Win64_CobaltStrike_BI_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.BI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 2b 04 24 48 03 44 24 ?? 48 03 44 24 ?? 0f b6 04 28 30 04 0b ff c3 48 83 ef ?? 0f 85 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}