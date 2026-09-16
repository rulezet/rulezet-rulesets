rule Trojan_Win64_CobaltStrike_NWU_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.NWU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c1 48 8b 45 ?? ba ?? ?? ?? ?? 48 f7 75 ?? 48 8b 45 ?? 48 01 d0 0f b6 00 31 c1 48 8b 55 ?? 48 8b 45 ?? 48 01 d0 89 ca 88 10 48 83 45 ?? ?? 48 8b 45 ?? 48 3b 45 ?? 72 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}