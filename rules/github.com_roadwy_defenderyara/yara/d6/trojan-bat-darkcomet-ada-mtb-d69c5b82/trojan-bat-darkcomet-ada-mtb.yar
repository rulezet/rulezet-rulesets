rule Trojan_BAT_DarkComet_ADA_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.ADA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0c 02 02 8e b7 17 da 91 1f 70 61 0d 02 8e b7 17 d6 8d 1e 00 00 01 0b 16 02 8e b7 17 da 13 06 13 05 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}