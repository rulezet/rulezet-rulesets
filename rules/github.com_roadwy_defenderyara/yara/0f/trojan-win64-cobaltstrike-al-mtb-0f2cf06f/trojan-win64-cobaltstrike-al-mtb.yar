rule Trojan_Win64_CobaltStrike_AL_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.AL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 29 c0 8b 05 ?? ?? ?? ?? 41 29 c0 44 89 c0 4c 63 c0 48 8b 45 ?? 4c 01 c0 0f b6 00 31 c8 88 02 83 45 ?? ?? 8b 45 ?? 3b 45 ?? 0f 82 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}