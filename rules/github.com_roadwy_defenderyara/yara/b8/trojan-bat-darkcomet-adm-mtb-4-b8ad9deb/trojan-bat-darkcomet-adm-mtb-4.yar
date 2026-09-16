rule Trojan_BAT_DarkComet_ADM_MTB_4{
	meta:
		description = "Trojan:BAT/DarkComet.ADM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0d 2b 1e 02 7b ?? 00 00 04 07 02 7b ?? 00 00 04 07 91 02 7b ?? 00 00 04 09 91 61 d2 9c 09 17 58 0d 09 02 7b ?? 00 00 04 8e 69 fe 04 13 04 11 04 2d d1 07 17 58 0b } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}