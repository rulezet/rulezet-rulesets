rule Trojan_Win64_CobaltStrike_LP_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.LP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 8b c0 99 83 e2 ?? 03 c2 83 e0 ?? 2b c2 48 63 c8 42 0f b6 04 19 43 32 04 0a 41 88 01 41 ff c0 49 ff c1 41 81 f8 ?? ?? ?? ?? 72 d4 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}