rule Trojan_Win64_CobaltStrike_YBL_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.YBL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 d1 8b ca 81 c1 7c db 03 00 48 8b 94 24 98 00 00 00 8b 44 02 18 33 c1 b9 04 00 00 00 48 6b c9 01 48 8b 94 24 98 00 00 00 89 44 0a 18 8b 44 24 38 c1 e8 08 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}