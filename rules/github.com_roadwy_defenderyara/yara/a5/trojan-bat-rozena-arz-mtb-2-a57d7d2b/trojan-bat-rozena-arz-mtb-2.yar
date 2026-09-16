rule Trojan_BAT_Rozena_ARZ_MTB_2{
	meta:
		description = "Trojan:BAT/Rozena.ARZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 13 16 2b 15 07 11 16 07 11 16 91 20 fa 00 00 00 61 d2 9c 11 16 17 58 13 16 11 16 07 8e 69 32 e4 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}