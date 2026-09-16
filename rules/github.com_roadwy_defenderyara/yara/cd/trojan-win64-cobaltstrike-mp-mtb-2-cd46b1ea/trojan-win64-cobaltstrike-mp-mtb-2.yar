rule Trojan_Win64_CobaltStrike_MP_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.MP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {42 79 46 64 69 5a } 		$a_01_1 = {56 73 58 43 7a 63 72 } 		$a_01_2 = {56 4a 69 44 54 } 		$a_01_3 = {77 65 65 75 6c 73 66 37 36 33 62 73 31 2e 64 6c 6c } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}