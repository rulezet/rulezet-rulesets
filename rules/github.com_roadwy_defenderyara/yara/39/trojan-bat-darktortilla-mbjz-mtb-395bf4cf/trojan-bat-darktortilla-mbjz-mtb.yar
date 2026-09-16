rule Trojan_BAT_DarkTortilla_MBJZ_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.MBJZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {64 32 61 38 66 30 34 65 2d 65 63 39 32 2d 34 62 36 66 2d 61 30 38 36 2d 62 65 34 39 35 30 66 61 37 65 66 37 } 		$a_01_1 = {46 62 32 71 31 4c 38 57 6d 50 67 30 6e 39 42 35 4e 65 4a 79 37 34 51 73 72 36 41 33 43 78 59 70 32 31 53 } 		$a_01_2 = {35 66 65 37 32 37 33 35 33 36 62 64 31 62 2e 52 65 73 6f 75 72 63 65 73 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}