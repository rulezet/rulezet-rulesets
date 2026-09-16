rule Trojan_BAT_Razy_BAA_MTB{
	meta:
		description = "Trojan:BAT/Razy.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 06 07 02 07 91 7e 01 00 00 04 07 7e 01 00 00 04 8e 69 5d 91 61 d2 9c 00 07 17 58 0b 07 02 8e 69 fe 04 0d 09 2d d9 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}