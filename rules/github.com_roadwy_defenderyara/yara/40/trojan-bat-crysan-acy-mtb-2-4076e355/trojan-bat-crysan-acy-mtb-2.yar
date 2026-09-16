rule Trojan_BAT_Crysan_ACY_MTB_2{
	meta:
		description = "Trojan:BAT/Crysan.ACY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {18 11 23 58 19 5d 13 26 19 8d ?? 00 00 01 13 27 11 27 16 12 20 28 ?? 00 00 0a 9c 11 27 17 12 20 28 ?? 00 00 0a 9c 11 27 18 12 20 28 ?? 00 00 0a 9c 11 22 16 fe 02 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}