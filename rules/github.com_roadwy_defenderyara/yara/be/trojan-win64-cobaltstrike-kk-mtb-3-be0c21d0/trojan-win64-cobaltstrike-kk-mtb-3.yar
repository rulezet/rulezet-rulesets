rule Trojan_Win64_CobaltStrike_KK_MTB_3{
	meta:
		description = "Trojan:Win64/CobaltStrike.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff c0 89 44 24 ?? 8b 44 24 ?? 39 44 24 04 73 ?? 8b 44 24 ?? 99 81 e2 ?? ?? ?? ?? 03 c2 25 ?? ?? ?? ?? 2b c2 88 04 24 8b 44 24 ?? 0f b6 0c 24 48 8b 54 24 ?? 0f be 04 02 33 c1 8b 4c 24 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}