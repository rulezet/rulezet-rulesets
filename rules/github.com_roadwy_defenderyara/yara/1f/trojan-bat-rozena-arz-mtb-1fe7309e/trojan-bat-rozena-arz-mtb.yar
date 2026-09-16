rule Trojan_BAT_Rozena_ARZ_MTB{
	meta:
		description = "Trojan:BAT/Rozena.ARZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 01 00 00 70 0a 28 01 00 00 0a 16 9a 28 02 00 00 0a 06 28 03 00 00 0a 39 00 00 00 00 2a } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}