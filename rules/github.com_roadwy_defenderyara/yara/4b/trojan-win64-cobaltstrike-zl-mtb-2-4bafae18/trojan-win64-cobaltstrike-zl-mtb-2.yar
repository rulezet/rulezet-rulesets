rule Trojan_Win64_CobaltStrike_ZL_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.ZL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 44 24 60 bb 03 00 00 00 48 8b 4c 24 70 31 ff be 00 80 00 00 49 89 f8 49 89 f9 49 89 fa e8 f2 b4 fc ff } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}