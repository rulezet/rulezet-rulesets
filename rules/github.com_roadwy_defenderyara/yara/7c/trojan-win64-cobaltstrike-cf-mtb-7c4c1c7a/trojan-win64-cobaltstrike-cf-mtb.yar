rule Trojan_Win64_CobaltStrike_CF_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 63 d0 48 8b 45 ?? 48 01 d0 0f b6 08 8b 45 ?? 48 63 d0 48 8b 45 ?? 48 01 d0 44 89 c2 31 ca 88 10 83 45 ?? ?? 83 45 ?? ?? 8b 45 ?? 48 98 48 3b 45 ?? 72 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}