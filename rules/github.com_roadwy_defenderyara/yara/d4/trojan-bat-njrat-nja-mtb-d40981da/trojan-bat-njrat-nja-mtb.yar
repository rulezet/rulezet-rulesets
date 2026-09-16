rule Trojan_BAT_NjRat_NJA_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NJA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {64 e0 07 11 0e 11 0f 19 58 58 e0 91 1f 18 62 07 11 0e 11 0f 18 58 58 e0 91 1f 10 62 60 07 } 		$a_01_1 = {6d 69 6e 69 20 63 61 6c 63 75 6c 61 74 6f 72 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}