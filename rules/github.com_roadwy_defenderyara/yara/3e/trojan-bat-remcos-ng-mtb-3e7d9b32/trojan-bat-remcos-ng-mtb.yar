rule Trojan_BAT_Remcos_NG_MTB{
	meta:
		description = "Trojan:BAT/Remcos.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {00 03 4b 04 4b 61 1f 7b 58 0a 03 4b 0b 03 04 4b 54 04 07 54 } 		$a_01_1 = {5f 0a 06 16 fe 01 0c 08 2c 04 00 17 0a 00 } 		$a_81_2 = {33 64 61 64 32 62 65 31 2d 64 39 63 32 2d 34 38 34 33 2d 62 31 38 39 2d 30 36 33 63 31 30 34 35 38 64 64 37 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_81_2  & 1)*2) >=4
 
}