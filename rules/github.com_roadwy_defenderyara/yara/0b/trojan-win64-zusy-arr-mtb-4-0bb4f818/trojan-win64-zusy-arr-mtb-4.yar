rule Trojan_Win64_Zusy_ARR_MTB_4{
	meta:
		description = "Trojan:Win64/Zusy.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {0b 07 2c 11 07 8e 2c 0d 16 0a 08 07 28 ?? ?? ?? ?? 14 0b 2b 19 06 1b 2f 04 06 17 58 0a 1f 0f 06 5a 6c } 		$a_03_1 = {2b 07 08 07 28 ?? ?? ?? ?? de 18 26 de 15 } 	condition:
		((#a_03_0  & 1)*15+(#a_03_1  & 1)*5) >=20
 
}