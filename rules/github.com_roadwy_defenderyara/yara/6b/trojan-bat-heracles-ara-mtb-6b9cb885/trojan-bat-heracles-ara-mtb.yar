rule Trojan_BAT_Heracles_ARA_MTB{
	meta:
		description = "Trojan:BAT/Heracles.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {24 63 63 37 66 61 64 30 33 2d 38 31 36 65 2d 34 33 32 63 2d 39 62 39 32 2d 30 30 31 66 32 64 33 35 38 33 38 38 } 		$a_01_1 = {73 65 72 76 65 72 31 2e 65 78 65 } 		$a_01_2 = {2e 72 65 73 6f 75 72 63 65 73 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}