rule TrojanDropper_BAT_Bepush_C_3{
	meta:
		description = "TrojanDropper:BAT/Bepush.C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {46 6c 61 73 68 20 55 70 64 61 74 65 } 		$a_80_1 = {5c 53 45 78 74 65 6e 73 69 6f 6e } 		$a_80_2 = {59 6f 6b 45 78 65 2e 65 78 65 } 		$a_80_3 = {46 61 63 65 62 6f 6f 6b } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}