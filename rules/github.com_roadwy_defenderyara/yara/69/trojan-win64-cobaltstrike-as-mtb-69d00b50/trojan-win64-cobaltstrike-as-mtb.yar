rule Trojan_Win64_CobaltStrike_AS_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {45 0f af d1 41 01 d2 4d 63 d2 42 8a 04 11 41 30 04 37 e9 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}