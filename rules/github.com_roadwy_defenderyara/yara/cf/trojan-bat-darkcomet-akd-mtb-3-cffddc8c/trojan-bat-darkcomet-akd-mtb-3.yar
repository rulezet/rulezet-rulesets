rule Trojan_BAT_DarkComet_AKD_MTB_3{
	meta:
		description = "Trojan:BAT/DarkComet.AKD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 17 58 20 00 01 00 00 5d 0b 11 05 11 08 07 91 58 20 00 01 00 00 5d 13 05 11 08 07 91 13 0d 11 08 07 11 08 11 05 91 9c 11 08 11 05 11 0d 9c 11 08 07 91 11 08 11 05 91 58 d2 20 00 01 00 00 5d 13 0c 02 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}