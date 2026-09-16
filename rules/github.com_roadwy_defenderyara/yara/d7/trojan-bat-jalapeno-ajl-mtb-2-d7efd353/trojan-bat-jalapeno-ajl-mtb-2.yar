rule Trojan_BAT_Jalapeno_AJL_MTB_2{
	meta:
		description = "Trojan:BAT/Jalapeno.AJL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 26 13 14 20 b4 00 00 00 95 58 80 ?? 00 00 04 11 2c 7e ?? 00 00 04 20 26 04 00 00 95 58 13 2c 11 2c 7e ?? 00 00 04 20 22 04 00 00 95 33 50 11 28 7e ?? 00 00 04 25 17 58 } 		$a_01_1 = {6b 62 64 65 73 32 53 65 61 72 64 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}