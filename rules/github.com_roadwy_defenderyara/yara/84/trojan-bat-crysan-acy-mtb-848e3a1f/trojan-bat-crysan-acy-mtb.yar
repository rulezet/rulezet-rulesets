rule Trojan_BAT_Crysan_ACY_MTB{
	meta:
		description = "Trojan:BAT/Crysan.ACY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 8e 69 17 58 20 00 30 00 00 1f 40 28 ?? 00 00 06 13 05 11 05 7e ?? 00 00 0a 28 ?? 00 00 0a 13 0c 11 0c 2c 05 ?? ?? ?? ?? ?? 11 04 11 05 06 06 8e 69 12 0e 28 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}