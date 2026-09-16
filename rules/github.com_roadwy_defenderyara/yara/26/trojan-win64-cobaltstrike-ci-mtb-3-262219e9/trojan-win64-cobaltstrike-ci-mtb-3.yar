rule Trojan_Win64_CobaltStrike_CI_MTB_3{
	meta:
		description = "Trojan:Win64/CobaltStrike.CI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {46 88 24 30 49 ff c6 4c 89 75 ?? 49 81 fe ?? ?? ?? ?? 74 ?? 44 89 f0 83 e0 0f 47 0f b6 24 3e 44 32 64 05 ?? 4c 3b 75 00 75 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}