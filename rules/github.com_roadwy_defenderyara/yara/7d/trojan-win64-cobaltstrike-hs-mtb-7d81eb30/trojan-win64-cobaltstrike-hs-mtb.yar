rule Trojan_Win64_CobaltStrike_HS_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.HS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {4c 8b 19 41 f7 f2 4d 01 cb 49 ff c1 89 d2 8a 44 11 ?? 41 30 03 eb } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}