rule Trojan_BAT_DarkComet_ADT_MTB_7{
	meta:
		description = "Trojan:BAT/DarkComet.ADT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {09 11 05 08 11 05 8e b7 5d 91 d6 11 07 08 91 d6 20 ff 00 00 00 5f 0d 11 07 08 91 13 08 11 07 08 11 07 09 91 9c 11 07 09 11 08 9c 08 17 d6 0c 08 11 0c } 		$a_01_1 = {0c 09 11 07 08 91 d6 20 ff 00 00 00 5f 0d 11 07 08 91 13 09 11 07 08 11 07 09 91 9c 11 07 09 11 09 9c 11 06 11 04 11 07 11 07 08 91 11 07 09 91 d6 20 ff 00 00 00 5f 91 06 11 04 91 61 9c 11 04 17 d6 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}