rule Trojan_BAT_DarkComet_ADO_MTB_2{
	meta:
		description = "Trojan:BAT/DarkComet.ADO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 8e 69 18 5a 03 8e 69 58 0a 2b 35 02 06 02 8e 69 5d 91 03 06 03 8e 69 5d 91 61 02 06 17 58 02 8e 69 5d 91 59 20 00 01 00 00 58 0b 07 20 00 01 00 00 5d d2 0c 02 06 02 8e 69 5d 08 9c 06 15 58 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}