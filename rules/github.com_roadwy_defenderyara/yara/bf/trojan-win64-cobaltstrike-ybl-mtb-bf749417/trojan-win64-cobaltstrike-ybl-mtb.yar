rule Trojan_Win64_CobaltStrike_YBL_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.YBL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 44 14 58 41 32 c7 88 04 0a 48 ff c2 84 c0 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}