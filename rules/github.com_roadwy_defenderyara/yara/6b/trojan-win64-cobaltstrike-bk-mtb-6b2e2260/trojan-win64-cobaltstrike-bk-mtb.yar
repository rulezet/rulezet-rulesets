rule Trojan_Win64_CobaltStrike_BK_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.BK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b c3 4d 8d 40 ?? 48 f7 e1 41 ff c2 48 c1 ea ?? 48 6b c2 ?? 48 2b c8 0f b6 44 8c ?? 41 30 40 ?? 49 63 ca 48 81 f9 ?? ?? ?? ?? 72 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}