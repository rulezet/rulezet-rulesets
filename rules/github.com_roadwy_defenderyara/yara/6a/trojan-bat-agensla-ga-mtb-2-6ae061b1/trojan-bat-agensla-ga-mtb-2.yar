rule Trojan_BAT_Agensla_GA_MTB_2{
	meta:
		description = "Trojan:BAT/Agensla.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {4d 41 52 43 55 53 2e 64 6c 6c } 		$a_80_1 = {6a 61 72 69 63 6f } 		$a_80_2 = {62 75 74 61 } 		$a_80_3 = {47 5a 69 70 53 74 72 65 61 6d } 		$a_80_4 = {49 6e 76 6f 6b 65 } 		$a_80_5 = {47 65 74 45 6e 74 72 79 41 73 73 65 6d 62 6c 79 } 		$a_80_6 = {d0 a1 d0 b5 d0 bd d1 8c d0 be d1 80 d0 b8 d1 82 d0 b0 } 	condition:
		((#a_81_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=7
 
}