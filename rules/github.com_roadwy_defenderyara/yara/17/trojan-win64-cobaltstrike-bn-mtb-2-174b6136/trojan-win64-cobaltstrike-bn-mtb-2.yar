rule Trojan_Win64_CobaltStrike_BN_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.BN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 3b 45 ?? 7d ?? 8b 45 ?? 48 63 d0 48 ?? ?? ?? 48 01 d0 44 0f b6 00 0f b6 4d ?? 8b 45 ?? 48 63 d0 48 ?? ?? ?? 48 01 d0 44 89 c2 31 ca 88 10 83 45 ?? ?? eb } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}