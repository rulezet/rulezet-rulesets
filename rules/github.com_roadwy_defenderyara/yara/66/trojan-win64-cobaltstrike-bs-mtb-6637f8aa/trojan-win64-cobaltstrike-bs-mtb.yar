rule Trojan_Win64_CobaltStrike_BS_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 04 24 48 8b 4c 24 20 0f be 44 01 04 48 8b 4c 24 20 0f b6 49 0b 2b c1 48 8b 4c 24 20 0f b6 49 0a 33 c1 8b 0c 24 48 8b 54 24 08 88 04 0a eb } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}