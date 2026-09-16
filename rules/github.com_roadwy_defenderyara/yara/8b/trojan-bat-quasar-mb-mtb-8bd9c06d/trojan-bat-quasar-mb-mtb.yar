rule Trojan_BAT_Quasar_MB_MTB{
	meta:
		description = "Trojan:BAT/Quasar.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0b 06 1a 73 23 00 00 0a 25 07 16 07 8e 69 6f 24 00 00 0a 73 25 00 00 0a 20 00 00 9f 24 20 00 80 48 28 6f 26 00 00 0a 8d 2c 00 00 01 0c 73 25 00 00 0a 08 6f 27 00 00 0a 25 08 16 08 8e 69 6f 24 00 00 0a } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}