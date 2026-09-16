rule Trojan_BAT_DarkComet_ADM_MTB_9{
	meta:
		description = "Trojan:BAT/DarkComet.ADM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 0a 2b 49 72 ?? 00 00 70 06 8c ?? 00 00 01 28 ?? 00 00 0a 0b 07 28 ?? 00 00 0a 6f ?? 00 00 0a 16 9a 0c 08 06 73 ?? 00 00 0a 0d 18 17 1c 73 } 		$a_03_1 = {16 0a 2b 1f 7e ?? 00 00 04 06 7e ?? 00 00 04 5d 91 0b 02 06 02 06 91 07 61 28 ?? 00 00 0a 9c 06 17 58 0a 06 02 8e 69 32 db } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}