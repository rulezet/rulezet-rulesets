rule Trojan_Win64_CobaltStrike_BW_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.BW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b f8 66 45 ?? ?? 75 ?? 45 33 db 41 ?? ?? ?? ?? ?? 49 8b c2 0f b7 00 41 8b c9 c1 c9 ?? 41 ff c3 03 c8 41 8b c3 49 03 c2 44 33 c9 80 38 ?? 75 ?? 48 ?? ?? ?? ?? ?? ?? ?? ff c2 46 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}