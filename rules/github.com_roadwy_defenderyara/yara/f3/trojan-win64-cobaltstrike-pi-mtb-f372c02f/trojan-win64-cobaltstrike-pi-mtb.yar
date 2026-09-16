rule Trojan_Win64_CobaltStrike_PI_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.PI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 01 c2 4c 63 c2 48 8b 55 10 4c 01 c2 0f b6 12 31 ca 88 10 83 45 f4 01 8b 45 f4 3b 45 20 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}