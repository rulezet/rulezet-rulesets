rule Trojan_BAT_DarkComet_ADM_MTB_2{
	meta:
		description = "Trojan:BAT/DarkComet.ADM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0c 2b 1d 07 08 8f ?? 00 00 01 25 71 ?? 00 00 01 02 08 06 5d 91 61 d2 81 ?? 00 00 01 08 17 58 0c 08 07 8e 69 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}