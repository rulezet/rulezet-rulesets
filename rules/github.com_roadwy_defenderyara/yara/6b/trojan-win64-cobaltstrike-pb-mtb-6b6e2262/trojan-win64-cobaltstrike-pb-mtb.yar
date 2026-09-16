rule Trojan_Win64_CobaltStrike_PB_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c8 f7 ea c1 fa ?? 89 c8 c1 f8 ?? 29 c2 89 d0 6b c0 ?? 29 c1 89 c8 48 98 4c 01 d0 0f b6 00 44 31 c8 41 88 00 83 85 1c 05 00 00 ?? 8b 85 1c 05 00 00 3b 85 04 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}