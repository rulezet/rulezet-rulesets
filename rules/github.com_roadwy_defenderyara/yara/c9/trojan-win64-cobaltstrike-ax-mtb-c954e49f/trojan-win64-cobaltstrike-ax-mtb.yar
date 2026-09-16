rule Trojan_Win64_CobaltStrike_AX_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.AX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 0f b6 44 1d ?? 30 04 3e 83 44 24 ?? ?? 81 7c 24 ?? ?? ?? ?? ?? 0f 85 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}