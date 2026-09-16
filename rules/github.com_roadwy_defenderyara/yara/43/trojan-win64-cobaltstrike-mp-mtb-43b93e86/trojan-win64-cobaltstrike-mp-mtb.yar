rule Trojan_Win64_CobaltStrike_MP_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 89 c2 83 e2 07 8a 54 15 00 32 14 07 88 14 06 48 ff c0 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}