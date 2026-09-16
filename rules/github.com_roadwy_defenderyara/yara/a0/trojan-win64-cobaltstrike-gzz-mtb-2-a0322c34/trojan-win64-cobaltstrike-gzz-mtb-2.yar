rule Trojan_Win64_CobaltStrike_GZZ_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {46 88 24 30 49 ff c6 4c 89 b5 ?? ?? ?? ?? 49 81 fe ?? ?? ?? ?? ?? ?? 44 89 f0 83 e0 0f 47 0f b6 24 3e 44 32 64 05 b0 4c 3b b5 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}