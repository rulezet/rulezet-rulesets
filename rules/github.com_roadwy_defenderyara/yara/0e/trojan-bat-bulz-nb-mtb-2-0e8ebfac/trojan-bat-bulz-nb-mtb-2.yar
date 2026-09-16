rule Trojan_BAT_Bulz_NB_MTB_2{
	meta:
		description = "Trojan:BAT/Bulz.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {08 06 16 20 00 04 00 00 6f 9a 00 00 0a 25 13 07 16 fe 02 13 0b 11 0b 2d c6 } 		$a_01_1 = {24 65 34 66 37 66 35 35 35 2d 38 61 32 33 2d 34 61 39 62 2d 39 61 33 63 2d 30 36 35 65 34 34 66 63 31 32 34 34 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}