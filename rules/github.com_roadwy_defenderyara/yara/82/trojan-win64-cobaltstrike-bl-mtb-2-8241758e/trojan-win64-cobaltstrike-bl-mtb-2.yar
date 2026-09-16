rule Trojan_Win64_CobaltStrike_BL_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.BL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b c6 48 ff c6 48 c1 ea ?? 48 69 d2 ?? ?? ?? ?? 48 2b c2 0f b6 44 04 ?? 41 30 43 ?? 48 ff c9 75 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}