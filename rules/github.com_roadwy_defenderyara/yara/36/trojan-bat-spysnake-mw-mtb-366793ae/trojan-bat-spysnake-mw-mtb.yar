rule Trojan_BAT_SpySnake_MW_MTB{
	meta:
		description = "Trojan:BAT/SpySnake.MW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 "
		
	strings :
		$a_03_0 = {02 07 02 8e 69 5d 02 07 02 8e 69 5d 91 06 07 06 8e 69 5d 91 61 ?? ?? ?? ?? ?? 6e 02 07 17 58 02 8e 69 5d 91 } 		$a_01_1 = {67 65 74 53 74 61 6b 65 } 		$a_01_2 = {50 72 6f 6d 6f 43 6f 72 65 2e 50 72 6f 70 65 72 74 69 65 73 } 	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5) >=20
 
}