rule Trojan_Win64_CobaltStrike_RA_MTB_3{
	meta:
		description = "Trojan:Win64/CobaltStrike.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 ed 2b d5 c1 fa 04 8b c2 c1 e8 1f 03 d0 48 63 c5 83 c5 01 48 63 ca 48 6b c9 1c 48 03 c8 48 8b 44 24 ?? 42 8a 8c 39 ?? ?? ?? ?? 41 32 0c 00 41 88 0c 18 49 83 c0 01 3b 6c 24 ?? 72 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}