rule Trojan_BAT_Tedy_ARR_MTB_2{
	meta:
		description = "Trojan:BAT/Tedy.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 "
		
	strings :
		$a_03_0 = {07 2d 09 16 8d ?? ?? ?? ?? 0d de 24 07 08 6f } 		$a_03_1 = {07 02 16 02 8e 69 6f ?? ?? ?? ?? 0c 08 8e 69 1f 10 59 8d ?? ?? ?? ?? 0d 08 1f 10 09 16 09 8e 69 } 		$a_01_2 = {74 6d 70 5f 73 74 75 62 2e 65 78 65 } 	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*10+(#a_01_2  & 1)*6) >=20
 
}