rule Trojan_BAT_Injector_RR_MTB{
	meta:
		description = "Trojan:BAT/Injector.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6f 2b 00 00 0a 2c 07 07 0a 17 2b d9 de 3e 07 28 37 00 00 0a 28 49 00 00 0a 6f 2c 00 00 0a de 0e } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}