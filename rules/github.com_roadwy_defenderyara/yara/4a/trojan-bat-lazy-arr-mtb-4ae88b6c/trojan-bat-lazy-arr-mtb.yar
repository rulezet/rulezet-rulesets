rule Trojan_BAT_Lazy_ARR_MTB{
	meta:
		description = "Trojan:BAT/Lazy.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {0b 07 2d 04 16 0a 2b 6e 07 02 7b } 		$a_01_1 = {2d 04 16 0a 2b 47 02 07 02 7b } 	condition:
		((#a_01_0  & 1)*9+(#a_01_1  & 1)*11) >=20
 
}