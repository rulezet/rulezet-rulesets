rule TrojanClicker_BAT_Balamid_A_2{
	meta:
		description = "TrojanClicker:BAT/Balamid.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {2f 72 65 6b 6c 61 6d 2f 37 32 38 78 39 30 2e 68 74 6d 6c } 		$a_80_1 = {61 6b 65 65 67 6c 65 65 6e 61 6f 6e 64 63 6b 6b 6e 6c 68 66 6c 6d 69 68 66 67 6b 70 62 61 6e 65 } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}