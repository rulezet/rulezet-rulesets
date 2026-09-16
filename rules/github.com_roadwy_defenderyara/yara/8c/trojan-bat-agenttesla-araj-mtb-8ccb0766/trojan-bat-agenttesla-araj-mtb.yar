rule Trojan_BAT_Agenttesla_ARAJ_MTB{
	meta:
		description = "Trojan:BAT/Agenttesla.ARAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 20 00 01 00 00 13 18 11 17 17 58 13 19 11 17 20 00 ba 00 00 5d 13 1a 11 19 20 00 ba 00 00 5d 13 1b 08 11 1a 91 13 1c 09 11 17 1f 16 5d 91 13 1d 08 11 1b 91 11 18 58 13 1e 11 1c 11 1d 61 13 1f 11 1f 11 1e 59 13 20 08 11 1a 11 20 11 18 5d d2 9c 00 11 17 17 58 13 17 11 17 20 00 ba 00 00 fe 04 13 21 11 21 2d 98 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}