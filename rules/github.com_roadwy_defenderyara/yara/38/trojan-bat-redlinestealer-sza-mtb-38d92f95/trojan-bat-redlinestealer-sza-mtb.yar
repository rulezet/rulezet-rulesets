rule Trojan_BAT_RedlineStealer_SZA_MTB{
	meta:
		description = "Trojan:BAT/RedlineStealer.SZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {06 11 15 1f 1f 5f 8f 89 00 00 01 25 4a 11 12 11 15 1e 5a 1f 1f 5f 63 61 54 11 15 17 58 13 15 11 15 1a fe 04 13 16 11 16 2d d6 } 		$a_81_1 = {41 63 63 6f 75 6e 74 5f 50 61 6e 65 6c 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } 		$a_81_2 = {24 33 65 62 32 30 32 35 33 2d 39 64 63 37 2d 34 31 31 39 2d 39 61 31 36 2d 35 63 62 37 36 33 65 38 65 33 65 38 } 	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}