rule Trojan_Win64_CobaltStrike_BW_MTB_3{
	meta:
		description = "Trojan:Win64/CobaltStrike.BW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 2b c2 48 8d 0c ?? 49 63 d0 44 8b ?? ?? ?? ?? ?? 48 03 d1 48 8d 04 ?? 48 2b d0 48 2b 54 ?? ?? 48 03 54 ?? ?? 49 03 d4 48 03 94 ?? ?? ?? ?? ?? 42 0f b6 04 ?? 30 04 2b ff c3 48 83 ee 01 0f 85 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}