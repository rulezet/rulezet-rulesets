rule Trojan_BAT_DarkComet_AMT_MTB_3{
	meta:
		description = "Trojan:BAT/DarkComet.AMT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {02 08 91 02 08 17 58 91 1e 62 60 02 08 18 58 91 1f 10 62 60 02 08 19 58 91 1f 18 62 60 13 04 08 1a 58 0c 09 11 08 fe 02 13 11 } 		$a_01_1 = {0a 00 03 1a 5d 16 fe 01 16 fe 01 0c 08 2d 07 00 06 d3 4a 0b de 23 06 d3 47 1f 18 62 06 d3 17 d3 58 47 1f 10 62 60 06 d3 18 d3 58 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}