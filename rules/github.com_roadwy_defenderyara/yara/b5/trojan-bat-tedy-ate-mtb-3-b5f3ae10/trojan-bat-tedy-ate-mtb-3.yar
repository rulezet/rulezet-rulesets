rule Trojan_BAT_Tedy_ATE_MTB_3{
	meta:
		description = "Trojan:BAT/Tedy.ATE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {1f 0a fe 02 13 08 11 08 2c 1c 00 72 01 00 00 70 7e 01 00 00 04 28 19 00 00 0a 00 72 1d 00 00 70 80 01 00 00 04 00 00 06 1f 20 fe 01 13 09 11 09 2c 1a } 		$a_01_1 = {4b 65 79 4c 6f 67 67 65 72 44 65 6d 6f 5c 4b 65 79 4c 6f 67 67 65 72 44 65 6d 6f 5c 6f 62 6a 5c 44 65 62 75 67 5c 4b 65 79 4c 6f 67 67 65 72 44 65 6d 6f 2e 70 64 62 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}