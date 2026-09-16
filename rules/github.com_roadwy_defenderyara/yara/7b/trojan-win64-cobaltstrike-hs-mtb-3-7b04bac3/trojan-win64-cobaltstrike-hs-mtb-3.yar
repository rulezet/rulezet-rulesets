rule Trojan_Win64_CobaltStrike_HS_MTB_3{
	meta:
		description = "Trojan:Win64/CobaltStrike.HS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 3a 2f 2f 77 77 77 2e 66 6c 6e 74 70 2e 72 6f 2f 66 69 6e 74 70 2e 78 36 34 2e 62 69 6e } 		$a_81_1 = {55 70 64 61 74 69 6e 67 20 61 70 70 6c 69 63 61 74 69 6f 6e } 		$a_81_2 = {43 6f 6e 73 6f 6c 65 41 70 70 6c 69 63 61 74 69 6f 6e 36 2e 70 64 62 } 	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*1+(#a_81_2  & 1)*2) >=6
 
}