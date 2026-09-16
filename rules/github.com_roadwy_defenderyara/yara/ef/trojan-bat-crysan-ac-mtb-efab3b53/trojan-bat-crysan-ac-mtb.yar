rule Trojan_BAT_Crysan_AC_MTB{
	meta:
		description = "Trojan:BAT/Crysan.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 8e 69 8d 31 00 00 01 0a 02 8e 69 17 59 0b 16 0c 2b 0e 06 08 02 07 91 9c 07 17 59 0b 08 17 58 0c 08 06 8e 69 32 ec } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}