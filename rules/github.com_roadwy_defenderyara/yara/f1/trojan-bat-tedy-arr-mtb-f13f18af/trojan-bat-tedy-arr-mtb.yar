rule Trojan_BAT_Tedy_ARR_MTB{
	meta:
		description = "Trojan:BAT/Tedy.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {5d 58 61 d2 9c 08 17 58 0c 08 06 8e 69 fe 04 0d 09 2d dd } 		$a_01_1 = {4b 00 6a 00 51 00 72 00 4f 00 43 00 77 00 73 00 43 00 41 00 51 00 4f 00 44 00 30 00 6f 00 41 00 48 00 67 00 49 00 3d 00 } 	condition:
		((#a_01_0  & 1)*15+(#a_01_1  & 1)*5) >=20
 
}