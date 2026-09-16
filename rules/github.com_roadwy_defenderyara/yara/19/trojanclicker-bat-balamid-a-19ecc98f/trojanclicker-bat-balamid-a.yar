rule TrojanClicker_BAT_Balamid_A{
	meta:
		description = "TrojanClicker:BAT/Balamid.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {5c 63 73 72 73 73 2e 65 78 65 } 		$a_80_1 = {62 61 67 6c 61 6e 6d 61 64 69 } 		$a_80_2 = {2f 74 6f 79 32 2e 74 78 74 } 		$a_80_3 = {6f 6e 6d 6f 75 73 65 64 6f 77 6e } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}