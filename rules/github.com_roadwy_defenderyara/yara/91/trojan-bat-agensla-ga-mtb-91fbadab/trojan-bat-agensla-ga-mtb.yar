rule Trojan_BAT_Agensla_GA_MTB{
	meta:
		description = "Trojan:BAT/Agensla.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {46 75 63 6b 69 6e 67 } 		$a_80_1 = {4d 6f 74 68 65 72 46 75 63 6b 65 72 42 69 74 63 68 } 		$a_80_2 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } 		$a_80_3 = {68 74 74 70 3a 2f 2f 6c 69 76 65 72 70 6f 6f 6c 6f 66 63 66 61 6e 63 6c 75 62 2e 63 6f 6d 2f 6c 69 76 65 72 70 6f 6f 6c } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}