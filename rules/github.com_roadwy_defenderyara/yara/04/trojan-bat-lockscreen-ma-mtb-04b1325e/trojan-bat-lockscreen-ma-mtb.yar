rule Trojan_BAT_LockScreen_MA_MTB{
	meta:
		description = "Trojan:BAT/LockScreen.MA!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {24 61 36 35 66 30 61 65 34 2d 34 62 39 66 2d 34 34 65 35 2d 38 38 33 39 2d 35 35 37 39 30 39 38 64 38 38 39 38 } 		$a_01_1 = {74 72 6f 6c 6c 5f 76 69 72 75 73 } 		$a_01_2 = {68 00 65 00 72 00 6f 00 62 00 72 00 69 00 6e 00 65 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}