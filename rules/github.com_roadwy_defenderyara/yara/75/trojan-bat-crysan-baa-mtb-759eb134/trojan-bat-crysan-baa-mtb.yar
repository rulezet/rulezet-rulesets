rule Trojan_BAT_Crysan_BAA_MTB{
	meta:
		description = "Trojan:BAT/Crysan.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 04 05 06 58 0e 04 06 59 ?? ?? ?? ?? ?? 0b 07 3a 0b 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 7a 06 07 58 0a 06 0e 04 32 d7 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}