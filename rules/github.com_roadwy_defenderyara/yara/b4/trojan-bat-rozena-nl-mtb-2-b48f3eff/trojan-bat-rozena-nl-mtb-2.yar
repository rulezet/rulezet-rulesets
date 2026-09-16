rule Trojan_BAT_Rozena_NL_MTB_2{
	meta:
		description = "Trojan:BAT/Rozena.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {06 72 19 00 00 70 72 85 00 00 70 6f 12 00 00 0a 00 06 72 20 01 00 70 72 94 01 00 70 6f 12 00 00 0a 00 00 } 		$a_01_1 = {24 61 64 34 65 33 64 64 34 2d 33 61 39 62 2d 34 64 62 37 2d 61 31 38 31 2d 35 30 63 36 65 36 33 65 65 63 62 33 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}