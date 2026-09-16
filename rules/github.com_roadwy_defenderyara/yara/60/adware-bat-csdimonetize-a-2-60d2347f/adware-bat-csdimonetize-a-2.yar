rule Adware_BAT_CsdiMonetize_A_2{
	meta:
		description = "Adware:BAT/CsdiMonetize.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 61 6c 65 73 5f 63 61 6d 70 61 69 67 6e 5f 74 61 72 67 65 74 5f 69 64 } 		$a_01_1 = {75 73 65 72 5f 73 68 6f 77 5f 63 61 70 70 69 6e 67 } 		$a_01_2 = {53 61 6e 4f 6f 2e 50 72 6f 70 65 72 74 69 65 73 } 		$a_01_3 = {53 61 6e 4f 6f 2e 65 78 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}