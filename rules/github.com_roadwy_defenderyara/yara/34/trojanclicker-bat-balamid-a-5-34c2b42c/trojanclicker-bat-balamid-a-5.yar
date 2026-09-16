rule TrojanClicker_BAT_Balamid_A_5{
	meta:
		description = "TrojanClicker:BAT/Balamid.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {2f 72 65 6b 6c 61 6d 2f 37 32 38 78 39 30 2e 68 74 6d 6c } 		$a_80_1 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } 		$a_80_2 = {63 68 72 6f 6d 65 } 		$a_80_3 = {73 61 66 61 72 69 } 		$a_80_4 = {66 69 72 65 66 6f 78 } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}