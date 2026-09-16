rule Trojan_Win64_CobaltStrike_KH_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.KH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 88 0c 0a 99 41 f7 f9 48 63 d2 0f b6 04 17 41 88 04 0b 48 83 c1 ?? 48 81 f9 } 		$a_03_1 = {0f b6 d2 0f b6 84 14 ?? ?? ?? ?? 40 88 bc 14 ?? ?? ?? ?? 88 84 0c ?? ?? ?? ?? 02 84 14 ?? ?? ?? ?? 0f b6 c0 0f b6 84 04 ?? ?? ?? ?? 42 32 04 0e 43 88 04 08 49 83 c1 ?? 4c 39 cb 75 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}