rule Trojan_Win64_CobaltStrike_CA_MTB_3{
	meta:
		description = "Trojan:Win64/CobaltStrike.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c2 c1 e8 ?? 03 d0 8b c3 ff c3 6b d2 ?? 2b c2 48 63 c8 48 8b 44 24 ?? 42 8a 8c 09 ?? ?? ?? ?? 43 32 8c 08 ?? ?? ?? ?? 41 88 0c 00 48 63 c3 49 ff c0 48 3b 44 24 ?? 72 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}