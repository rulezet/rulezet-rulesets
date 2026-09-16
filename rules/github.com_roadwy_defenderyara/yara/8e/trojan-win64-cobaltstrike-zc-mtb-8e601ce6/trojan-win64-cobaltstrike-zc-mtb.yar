rule Trojan_Win64_CobaltStrike_ZC_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.ZC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 85 db 0f 84 ?? ?? ?? ?? 41 50 41 54 49 c7 c4 00 00 00 00 4d 89 e0 41 5c 49 01 c0 41 54 49 c7 c4 00 00 00 00 4d 01 c4 49 01 0c 24 41 5c ff 34 24 41 58 48 81 c4 ?? ?? ?? ?? 48 83 c0 ?? 83 eb 01 e9 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}