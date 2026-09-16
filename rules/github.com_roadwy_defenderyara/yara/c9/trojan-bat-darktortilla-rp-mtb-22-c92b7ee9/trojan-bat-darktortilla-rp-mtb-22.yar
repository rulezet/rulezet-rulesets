rule Trojan_BAT_DarkTortilla_RP_MTB_22{
	meta:
		description = "Trojan:BAT/DarkTortilla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {28 ba 00 00 06 0a 06 2c 02 2b 01 00 00 73 24 00 00 0a 28 4d 00 00 0a 28 69 01 00 06 00 de 0f 25 28 47 00 00 0a 0b 00 28 60 00 00 0a de 00 00 2a } 		$a_01_1 = {00 28 6f 00 00 06 16 fe 01 0b 07 2c 04 17 0a 2b 00 06 2a } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}