rule Trojan_Win64_CobaltStrike_AO_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.AO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 c2 89 d0 83 e0 01 02 04 11 83 e8 03 49 39 d0 88 04 11 48 8d 42 01 90 13 48 89 c2 89 d0 83 e0 01 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}