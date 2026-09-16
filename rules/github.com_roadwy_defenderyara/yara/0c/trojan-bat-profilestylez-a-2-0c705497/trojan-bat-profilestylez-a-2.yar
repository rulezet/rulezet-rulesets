rule Trojan_BAT_ProfileStylez_A_2{
	meta:
		description = "Trojan:BAT/ProfileStylez.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {54 4f 20 55 53 45 20 54 48 45 70 72 6f 66 69 6c 65 } 		$a_01_1 = {65 78 74 65 6e 73 69 6f 6e 5f 32 5f 35 5f 31 2e 63 72 78 } 		$a_01_2 = {61 6c 6c 6f 77 20 75 73 20 74 6f 20 64 69 73 70 6c 61 79 20 70 6f 70 2d 75 70 2c 20 70 6f 70 2d 75 6e 64 65 72 20 61 6e 64 20 6f 74 68 65 72 20 74 79 70 65 73 20 6f 66 20 61 64 76 65 72 74 69 73 65 6d 65 6e 74 73 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}