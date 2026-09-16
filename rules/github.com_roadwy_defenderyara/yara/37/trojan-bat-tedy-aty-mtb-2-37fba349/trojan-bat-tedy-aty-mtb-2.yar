rule Trojan_BAT_Tedy_ATY_MTB_2{
	meta:
		description = "Trojan:BAT/Tedy.ATY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 0a 2b 0d 02 06 02 06 91 03 61 d2 9c 06 17 58 0a 06 02 28 ?? 00 00 06 25 26 69 32 e7 } 		$a_01_1 = {16 0c 2b 1c 07 08 18 5b 02 08 18 28 63 00 00 06 25 26 1f 10 28 ac 00 00 06 25 26 9c 08 18 58 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}