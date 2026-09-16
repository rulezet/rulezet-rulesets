rule Trojan_BAT_Crysan_BAA_MTB_2{
	meta:
		description = "Trojan:BAT/Crysan.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {6f 11 00 00 0a 0c 08 6f 12 00 00 0a 0d 09 02 16 02 8e 69 6f 13 00 00 0a 13 04 dd 1a 00 00 00 09 39 06 00 00 00 09 6f 0b 00 00 0a dc 08 39 06 00 00 00 08 6f 0b 00 00 0a dc } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}