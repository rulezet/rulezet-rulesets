rule Trojan_Win64_CobaltStrike_SP_MTB_3{
	meta:
		description = "Trojan:Win64/CobaltStrike.SP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {30 5a 4e 41 33 45 5a 34 67 2e 65 78 65 } 		$a_81_1 = {30 5a 4e 41 33 45 5a 34 67 2e 78 6c 73 78 } 		$a_81_2 = {35 30 64 6c 78 4a 65 } 		$a_01_3 = {77 00 69 00 6e 00 72 00 61 00 72 00 73 00 66 00 78 00 6d 00 61 00 70 00 70 00 69 00 6e 00 67 00 66 00 69 00 6c 00 65 00 2e 00 74 00 6d 00 70 00 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}