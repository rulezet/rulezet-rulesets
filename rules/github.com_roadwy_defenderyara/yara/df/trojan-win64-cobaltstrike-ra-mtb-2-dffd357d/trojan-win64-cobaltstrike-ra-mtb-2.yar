rule Trojan_Win64_CobaltStrike_RA_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 ee c1 fa 03 8b c2 c1 e8 1f 03 d0 8b c6 ff c6 6b d2 21 2b c2 48 63 c8 48 8d 05 ?? ?? ?? ?? 8a 04 01 43 32 04 01 41 88 00 49 ff c0 3b f7 72 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}