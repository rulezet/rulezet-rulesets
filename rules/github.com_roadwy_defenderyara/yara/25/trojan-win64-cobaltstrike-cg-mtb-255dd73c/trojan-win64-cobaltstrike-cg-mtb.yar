rule Trojan_Win64_CobaltStrike_CG_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 c3 40 2a c7 24 10 32 03 40 32 c6 88 03 48 03 d9 49 3b dd 72 ?? 8b 44 24 ?? 49 ff c4 49 ff c6 49 ff cf 0f 85 } 	condition:
		((#a_03_0  & 1)*3) >=3
 
}