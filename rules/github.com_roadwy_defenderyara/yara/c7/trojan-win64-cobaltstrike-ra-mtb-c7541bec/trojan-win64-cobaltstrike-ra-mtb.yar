rule Trojan_Win64_CobaltStrike_RA_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {49 63 c6 48 8b 4d 88 0f b6 4c 08 01 30 4c 15 50 c6 44 24 7c 00 48 8d 55 e0 48 8d 4c 24 7c } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}