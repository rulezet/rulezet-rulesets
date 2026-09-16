rule Trojan_BAT_Remcos_ARR_MTB_3{
	meta:
		description = "Trojan:BAT/Remcos.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {16 13 15 2b 19 00 11 0f 11 15 11 0f 11 15 91 20 d2 02 00 00 59 d2 9c 00 11 15 17 58 13 15 11 15 11 0f 8e 69 } 		$a_01_1 = {32 30 32 33 43 72 79 70 74 73 44 6f 6e 65 5c 44 61 72 6b 4d 6f 64 65 46 6f 72 6d 73 5c 6f 62 6a 5c 44 65 62 75 67 5c 44 61 72 6b 4d 6f 64 65 46 6f 72 6d 73 2e 70 64 62 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}