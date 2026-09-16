rule Trojan_BAT_Heracles_AHE_MTB_4{
	meta:
		description = "Trojan:BAT/Heracles.AHE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 03 00 00 "
		
	strings :
		$a_03_0 = {13 12 20 f4 01 00 00 13 13 72 ?? ?? ?? 70 1a 8d 01 00 00 01 13 1d 11 1d 16 11 10 8c 22 00 00 01 a2 11 1d 17 11 11 } 		$a_01_1 = {3c 45 78 65 63 75 74 65 43 6f 6d 6d 61 6e 64 46 6f 72 54 65 6d 70 43 6f 6e 6e 65 63 74 69 6f 6e 3e 62 5f 5f } 		$a_01_2 = {74 65 6d 70 43 6f 6e 6e 65 63 74 69 6f 6e 73 4c 6f 63 6b } 	condition:
		((#a_03_0  & 1)*30+(#a_01_1  & 1)*20+(#a_01_2  & 1)*10) >=60
 
}