rule Trojan_BAT_DarkTortilla_RP_MTB_25{
	meta:
		description = "Trojan:BAT/DarkTortilla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {28 33 00 00 0a 0a 06 28 33 00 00 0a 28 ?? 01 00 06 de 0e 25 28 ?? 00 00 0a 0b 28 ?? 00 00 0a de 00 } 		$a_03_1 = {28 34 00 00 0a 0a 06 28 34 00 00 0a 28 ?? 01 00 06 de 0e 25 28 ?? 00 00 0a 0b 28 ?? 00 00 0a de 00 } 		$a_03_2 = {28 39 00 00 0a 0a 06 28 39 00 00 0a 28 ?? 01 00 06 00 de 0f 25 28 ?? 00 00 0a 0b 00 28 ?? 00 00 0a de 00 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}