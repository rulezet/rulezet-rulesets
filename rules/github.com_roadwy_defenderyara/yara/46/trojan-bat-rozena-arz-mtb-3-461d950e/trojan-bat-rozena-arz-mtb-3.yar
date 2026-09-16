rule Trojan_BAT_Rozena_ARZ_MTB_3{
	meta:
		description = "Trojan:BAT/Rozena.ARZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0b 16 13 06 2b 18 07 11 06 07 11 06 91 1f 22 61 20 ff 00 00 00 5f d2 9c 11 06 17 58 13 06 11 06 07 8e 69 32 e1 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}