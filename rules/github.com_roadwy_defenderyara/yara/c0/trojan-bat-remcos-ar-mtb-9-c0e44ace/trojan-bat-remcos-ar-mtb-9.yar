rule Trojan_BAT_Remcos_AR_MTB_9{
	meta:
		description = "Trojan:BAT/Remcos.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {7e 51 00 00 04 06 7e 51 00 00 04 06 91 20 89 03 00 00 59 d2 9c 00 06 17 58 0a 06 7e 51 00 00 04 8e 69 fe 04 0b 07 2d d7 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}