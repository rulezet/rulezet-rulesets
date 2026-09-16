rule Trojan_BAT_DarkComet_ADT_MTB_4{
	meta:
		description = "Trojan:BAT/DarkComet.ADT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {5d 0a 11 05 11 09 91 13 04 11 05 11 09 11 05 06 91 9c 11 05 06 11 04 9c 11 05 11 09 91 11 05 06 91 d6 20 00 01 00 00 5d 0b 03 50 11 0a 03 50 11 0a 91 11 05 07 91 61 9c 11 0a 17 d6 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}