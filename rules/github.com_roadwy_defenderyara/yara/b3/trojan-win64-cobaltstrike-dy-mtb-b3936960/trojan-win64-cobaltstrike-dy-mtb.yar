rule Trojan_Win64_CobaltStrike_DY_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.DY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 04 1f 30 03 48 ff c3 48 83 e9 01 75 ?? 48 83 ef ?? 0f 29 84 24 ?? ?? ?? ?? 48 83 ee 01 75 } 		$a_03_1 = {41 0f b6 84 38 ?? ?? ?? ?? 41 30 00 49 ff c0 48 83 e9 01 75 ?? 49 83 e9 01 75 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}