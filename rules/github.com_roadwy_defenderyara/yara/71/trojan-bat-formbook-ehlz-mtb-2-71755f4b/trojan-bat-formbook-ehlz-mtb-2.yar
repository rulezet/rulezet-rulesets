rule Trojan_BAT_Formbook_EHLZ_MTB_2{
	meta:
		description = "Trojan:BAT/Formbook.EHLZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {5a 11 0a 1a 63 61 61 13 0a 16 13 33 ?? ?? ?? ?? ?? 00 11 0a 11 33 1f 59 5a 61 13 34 00 02 11 32 11 33 ?? ?? ?? ?? ?? 13 35 04 03 ?? ?? ?? ?? ?? 59 13 36 11 36 13 37 11 37 19 fe 02 13 3d 11 3d 2c 03 19 13 37 11 37 16 fe 04 13 3e 11 3e 2c 03 16 13 37 11 0a 16 5f 13 38 11 38 19 5d 13 39 17 11 38 58 19 5d 13 3a 18 11 38 58 19 5d 13 3b 19 8d 49 00 00 01 13 3c 11 3c 16 12 35 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}