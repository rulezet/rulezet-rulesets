rule Trojan_Win64_CobaltStrike_CA_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {80 44 24 47 02 c6 44 24 48 55 } 		$a_01_1 = {80 44 24 4a 24 c6 44 24 4b 4b } 		$a_01_2 = {80 44 24 4f 0a c6 44 24 50 3b } 		$a_01_3 = {80 44 24 48 11 c6 44 24 49 4a } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}