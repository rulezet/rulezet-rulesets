rule Trojan_BAT_Marsilia_AMI_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.AMI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 00 06 0b 16 0c 2b 27 07 08 9a 0d 00 09 6f 36 00 00 0a 72 01 00 00 70 1b 6f 37 00 00 0a 13 04 11 04 2c 06 00 17 13 05 2b 10 00 08 17 58 0c 08 07 8e 69 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}