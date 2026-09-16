rule Trojan_BAT_DarkComet_ADK_MTB_20{
	meta:
		description = "Trojan:BAT/DarkComet.ADK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {16 02 50 8e b7 17 da 0c 0b 2b 37 02 50 07 02 50 8e b7 5d 02 50 07 02 50 8e b7 5d 91 03 07 03 8e b7 5d 91 61 02 50 07 17 d6 02 50 8e b7 5d 91 da 20 00 01 00 00 d6 20 00 01 00 00 5d b4 9c 07 17 d6 0b 07 08 31 c5 } 		$a_01_1 = {54 00 68 00 65 00 45 00 6c 00 65 00 76 00 61 00 74 00 6f 00 72 00 2e 00 74 00 78 00 74 00 } 		$a_01_2 = {53 00 7a 00 43 00 57 00 79 00 45 00 52 00 4f 00 77 00 4b 00 6a 00 6a 00 4c 00 54 00 67 00 49 00 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}