rule TrojanClicker_BAT_Balamid_A_3{
	meta:
		description = "TrojanClicker:BAT/Balamid.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {5c 74 61 73 6b 36 34 2e 65 78 65 } 		$a_80_1 = {5c 73 79 73 74 65 6d 2e 65 78 65 } 		$a_80_2 = {77 69 6e 74 61 73 6b 33 32 2e 63 6f 6d } 		$a_80_3 = {2f 74 6f 79 32 2e 74 78 74 } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}