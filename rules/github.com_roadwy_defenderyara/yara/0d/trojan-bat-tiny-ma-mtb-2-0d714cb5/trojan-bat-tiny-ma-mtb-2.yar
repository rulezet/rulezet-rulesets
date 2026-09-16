rule Trojan_BAT_Tiny_MA_MTB_2{
	meta:
		description = "Trojan:BAT/Tiny.MA!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {72 b3 00 00 70 28 06 00 00 06 de 03 } 		$a_01_1 = {62 65 64 66 62 34 31 37 2d 61 32 64 66 2d 34 61 65 35 2d 62 62 31 63 2d 31 62 38 63 30 30 62 33 65 62 37 31 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}