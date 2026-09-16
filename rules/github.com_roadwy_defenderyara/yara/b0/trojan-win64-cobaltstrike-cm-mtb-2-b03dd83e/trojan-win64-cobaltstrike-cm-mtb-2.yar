rule Trojan_Win64_CobaltStrike_CM_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.CM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c1 d3 fa 41 89 d0 0f b6 44 24 ?? 0f b6 d0 0f b6 44 24 ?? 0f b6 c8 b8 ?? ?? ?? ?? 29 c8 89 c1 d3 e2 89 d0 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}