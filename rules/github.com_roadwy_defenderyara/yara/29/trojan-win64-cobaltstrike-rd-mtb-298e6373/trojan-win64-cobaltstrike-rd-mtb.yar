rule Trojan_Win64_CobaltStrike_RD_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b e8 44 8b f3 41 b9 40 00 00 00 41 b8 00 10 00 00 8b d3 33 c9 ff 15 0a ee } 		$a_01_1 = {0f 57 c0 48 8d 53 08 48 89 0b 48 8d 48 08 0f 11 02 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}