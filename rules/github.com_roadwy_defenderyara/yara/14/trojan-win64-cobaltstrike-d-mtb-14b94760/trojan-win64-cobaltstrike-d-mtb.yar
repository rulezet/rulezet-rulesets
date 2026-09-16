rule Trojan_Win64_CobaltStrike_D_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 89 c9 89 c8 41 f7 ea c1 fa 04 89 c8 c1 f8 1f 29 c2 89 d0 c1 e0 06 8d 14 50 41 29 d1 4d 63 c9 48 8b 05 ?? ?? ?? ?? 42 0f b6 04 08 32 44 0c 60 41 88 04 08 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}