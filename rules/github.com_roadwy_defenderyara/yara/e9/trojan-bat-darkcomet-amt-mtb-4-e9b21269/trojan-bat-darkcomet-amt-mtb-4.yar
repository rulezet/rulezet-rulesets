rule Trojan_BAT_DarkComet_AMT_MTB_4{
	meta:
		description = "Trojan:BAT/DarkComet.AMT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 03 11 05 16 6f ?? 00 00 06 28 ?? 00 00 0a 0b 02 03 11 05 17 6f ?? 00 00 06 28 ?? 00 00 0a 0d 18 09 d8 6c 04 28 ?? 00 00 0a 59 07 6c 59 28 } 		$a_01_1 = {03 11 05 08 20 00 01 00 00 5d b4 9c 03 11 05 17 d6 11 04 20 00 01 00 00 5d b4 9c 11 05 18 d6 } 	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}