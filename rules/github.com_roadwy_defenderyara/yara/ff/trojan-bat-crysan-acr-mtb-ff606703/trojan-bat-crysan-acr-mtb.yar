rule Trojan_BAT_Crysan_ACR_MTB{
	meta:
		description = "Trojan:BAT/Crysan.ACR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a de 03 26 de 00 72 ?? 00 00 70 0a 72 ?? 00 00 70 06 28 ?? 00 00 0a 26 2a } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}