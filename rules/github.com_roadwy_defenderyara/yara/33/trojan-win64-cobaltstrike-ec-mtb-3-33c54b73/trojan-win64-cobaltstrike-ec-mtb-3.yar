rule Trojan_Win64_CobaltStrike_EC_MTB_3{
	meta:
		description = "Trojan:Win64/CobaltStrike.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_01_0 = {c7 44 24 50 5c 00 00 00 c7 44 24 48 65 00 00 00 c7 44 24 40 70 00 00 00 c7 44 24 38 69 00 00 00 c7 44 24 30 70 00 00 00 c7 44 24 28 5c 00 00 00 c7 44 24 20 2e } 		$a_81_1 = {25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 6b 69 72 69 74 6f 5c 61 73 75 6e 61 } 	condition:
		((#a_01_0  & 1)*5+(#a_81_1  & 1)*2) >=7
 
}