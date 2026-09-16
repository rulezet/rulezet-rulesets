rule Trojan_Win64_CobaltStrike_BP_MTB_3{
	meta:
		description = "Trojan:Win64/CobaltStrike.BP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 8a 0c 10 45 88 c8 41 f6 d0 44 88 84 24 [0-04] 41 80 e0 ?? 44 88 84 24 [0-04] 41 80 e1 ?? 45 08 c8 44 88 84 24 [0-04] 41 80 f0 ?? 44 88 04 10 89 c8 83 c0 01 89 84 24 [0-04] 83 e9 ?? 89 8c 24 [0-04] 0f 92 c1 89 84 24 [0-04] 0f } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}