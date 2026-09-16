rule Trojan_BAT_Heracles_AHE_MTB_2{
	meta:
		description = "Trojan:BAT/Heracles.AHE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {0c 07 16 08 6e 28 18 00 00 0a 07 8e 69 28 19 00 00 0a 7e 1a 00 00 0a 26 16 0d 7e 1a 00 00 0a 13 04 16 16 08 11 04 16 12 03 28 } 		$a_01_1 = {73 68 6c 6c 63 72 79 70 74 72 75 6e 6e } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}