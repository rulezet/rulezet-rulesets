rule Trojan_BAT_Noon_NBL_MTB{
	meta:
		description = "Trojan:BAT/Noon.NBL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 0e 11 16 8f 05 00 00 01 25 47 7e 03 00 00 04 19 11 16 5f 19 62 1f 1f 5f 63 d2 61 d2 52 17 11 16 58 13 16 11 16 11 0e 8e 69 33 d4 } 		$a_01_1 = {11 34 11 0d 1d 5f 91 13 1f 11 1f 19 62 11 1f 1b 63 60 d2 13 1f 11 05 11 0d 11 05 11 0d 91 11 1f 61 d2 9c 11 0d 17 58 13 0d 11 0d 11 08 32 d1 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}