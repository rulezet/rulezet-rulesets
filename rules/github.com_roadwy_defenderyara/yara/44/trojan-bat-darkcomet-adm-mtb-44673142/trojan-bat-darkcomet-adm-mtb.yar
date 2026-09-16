rule Trojan_BAT_DarkComet_ADM_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.ADM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {da 0d 0c 2b 3f 07 08 91 1f 1f fe 02 07 08 91 1f 7f fe 04 5f 2c 14 07 08 13 04 11 04 07 11 04 91 08 1f 1f 5d 18 d6 b4 59 86 9c } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}