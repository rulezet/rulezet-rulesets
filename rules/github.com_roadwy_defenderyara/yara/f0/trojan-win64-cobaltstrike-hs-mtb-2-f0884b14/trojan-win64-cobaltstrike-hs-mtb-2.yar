rule Trojan_Win64_CobaltStrike_HS_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.HS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 c3 4c 8b 2d ?? ?? ?? ?? 31 f6 39 f7 7e ?? 48 89 f0 83 e0 ?? 41 8a 04 04 32 44 35 ?? 88 04 33 48 ff c6 41 ff d5 41 ff d5 eb } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}