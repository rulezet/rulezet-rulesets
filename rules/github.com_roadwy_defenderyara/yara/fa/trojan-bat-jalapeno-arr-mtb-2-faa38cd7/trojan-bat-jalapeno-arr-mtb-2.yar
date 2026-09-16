rule Trojan_BAT_Jalapeno_ARR_MTB_2{
	meta:
		description = "Trojan:BAT/Jalapeno.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {0d 08 09 6f ?? ?? ?? ?? 00 07 8e 69 09 8e 69 58 8d ?? ?? ?? ?? 13 04 07 16 11 04 16 07 8e 69 } 		$a_01_1 = {09 16 11 04 07 8e 69 09 8e 69 28 } 	condition:
		((#a_03_0  & 1)*12+(#a_01_1  & 1)*8) >=20
 
}