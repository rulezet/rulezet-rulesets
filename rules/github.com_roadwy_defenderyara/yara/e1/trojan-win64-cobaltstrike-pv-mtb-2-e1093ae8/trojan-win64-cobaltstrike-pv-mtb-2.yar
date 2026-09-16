rule Trojan_Win64_CobaltStrike_PV_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.PV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 04 24 ff c0 89 04 24 48 63 04 24 48 3d [0-04] 73 ?? 48 63 04 ?? 48 8d 0d ?? ?? ?? ?? 0f b6 04 01 03 44 24 ?? 33 44 24 ?? 48 63 0c 24 48 8d 15 ?? ?? ?? ?? 88 04 0a eb } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}