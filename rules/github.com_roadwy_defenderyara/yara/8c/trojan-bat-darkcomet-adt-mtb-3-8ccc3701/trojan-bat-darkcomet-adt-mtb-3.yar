rule Trojan_BAT_DarkComet_ADT_MTB_3{
	meta:
		description = "Trojan:BAT/DarkComet.ADT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 13 08 2b 25 11 06 11 08 11 04 11 08 91 11 05 11 08 11 05 8e 69 5d 91 11 07 58 20 ff 00 00 00 5f 61 d2 9c 11 08 17 58 13 08 11 08 11 06 8e 69 17 59 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}