rule Trojan_BAT_DarkComet_AMT_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.AMT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 0c 2b 12 08 06 08 06 93 02 7b 08 00 00 04 07 91 04 60 61 d1 9d 06 17 59 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}