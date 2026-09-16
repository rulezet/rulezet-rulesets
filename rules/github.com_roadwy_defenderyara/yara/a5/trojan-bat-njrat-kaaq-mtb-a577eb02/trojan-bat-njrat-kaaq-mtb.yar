rule Trojan_BAT_NjRAT_KAAQ_MTB{
	meta:
		description = "Trojan:BAT/NjRAT.KAAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 "
		
	strings :
		$a_01_0 = {2c 37 33 2c 37 38 2c 37 31 2c 38 38 2c 38 38 2c 38 30 2c 36 35 2c } 		$a_01_1 = {2c 37 33 2c 37 38 2c 37 31 2c 38 38 2c 38 38 2c 38 30 2c 36 35 2c 36 38 2c 36 38 2c 37 } 		$a_01_2 = {38 30 2c 36 35 2c 36 38 2c 36 38 2c 37 33 2c 37 38 2c 37 31 2c 38 30 2c 36 35 2c } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3) >=9
 
}