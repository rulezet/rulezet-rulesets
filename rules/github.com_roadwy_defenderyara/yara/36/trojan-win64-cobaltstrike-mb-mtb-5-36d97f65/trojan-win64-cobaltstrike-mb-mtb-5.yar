rule Trojan_Win64_CobaltStrike_MB_MTB_5{
	meta:
		description = "Trojan:Win64/CobaltStrike.MB!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 83 80 00 00 00 48 8b 8b e0 00 00 00 42 31 04 01 49 83 c0 04 8b 83 e8 00 00 00 01 83 80 00 00 00 8b 43 24 ff c8 01 83 d0 00 00 00 8b 83 94 00 00 00 8b 93 a8 00 00 00 81 c2 37 9f fd ff 03 53 74 0f af c2 89 83 94 00 00 00 b8 6f 15 f8 ff } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}