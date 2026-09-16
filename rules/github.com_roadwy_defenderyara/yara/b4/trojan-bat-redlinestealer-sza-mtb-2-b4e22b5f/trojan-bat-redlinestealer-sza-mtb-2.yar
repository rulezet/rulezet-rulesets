rule Trojan_BAT_RedlineStealer_SZA_MTB_2{
	meta:
		description = "Trojan:BAT/RedlineStealer.SZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {24 39 39 36 61 33 36 65 34 2d 36 34 63 38 2d 34 63 34 38 2d 62 63 33 33 2d 39 35 64 37 64 63 62 63 64 30 39 65 } 		$a_81_1 = {4a 59 4d 5f 50 72 6f 6a 65 63 74 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } 		$a_00_2 = {00 11 04 11 14 8f 60 00 00 01 25 47 11 0e 11 14 1e 5a 1f 1f 5f 63 d2 61 d2 52 00 11 14 17 58 13 14 11 14 1a fe 04 13 15 11 15 2d d4 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}