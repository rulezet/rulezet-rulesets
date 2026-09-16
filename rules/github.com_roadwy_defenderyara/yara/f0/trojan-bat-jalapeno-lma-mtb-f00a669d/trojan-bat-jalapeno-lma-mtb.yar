rule Trojan_BAT_Jalapeno_LMA_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.LMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {72 b4 00 00 70 28 08 00 00 0a 26 de 03 26 de 00 2a } 		$a_01_1 = {72 01 00 00 70 72 b0 00 00 70 02 7b 02 00 00 04 28 06 00 00 0a 28 07 00 00 0a 26 de 03 26 de 00 2a } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*20) >=30
 
}