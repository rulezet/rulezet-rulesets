rule Trojan_BAT_Jalapeno_ARR_MTB_3{
	meta:
		description = "Trojan:BAT/Jalapeno.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_81_0 = {24 63 37 39 61 66 31 63 39 2d 32 33 39 63 2d 34 37 64 34 2d 62 33 33 66 2d 35 35 32 65 63 30 64 62 33 63 36 35 } 		$a_81_1 = {52 75 6e 6e 65 72 5f 41 2e 4d 79 } 	condition:
		((#a_81_0  & 1)*8+(#a_81_1  & 1)*12) >=20
 
}