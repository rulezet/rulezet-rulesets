rule Trojan_BAT_Remcos_AMAA_MTB_2{
	meta:
		description = "Trojan:BAT/Remcos.AMAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 11 0a 11 04 5d 13 0b 11 0a 11 05 5d 13 0c 08 11 0b 91 13 0d 09 11 0c 6f ?? 00 00 0a 13 0e 08 11 0a 17 58 11 04 5d 91 13 0f 11 0d 11 0e 11 0f 28 ?? 00 00 06 13 10 08 11 0b 11 10 20 00 01 00 00 5d d2 9c 00 11 0a 17 59 13 0a 11 0a 16 fe 04 16 fe 01 13 11 11 11 2d a7 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}