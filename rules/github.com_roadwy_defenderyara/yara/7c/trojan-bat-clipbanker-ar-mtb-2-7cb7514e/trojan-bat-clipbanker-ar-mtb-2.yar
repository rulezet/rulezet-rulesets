rule Trojan_BAT_ClipBanker_AR_MTB_2{
	meta:
		description = "Trojan:BAT/ClipBanker.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 "
		
	strings :
		$a_01_0 = {28 26 00 00 0a 2d 05 dd 86 00 00 00 28 27 00 00 0a 0a 06 28 28 00 00 0a 2d 0d 06 7e 2c 00 00 04 28 1c 00 00 0a 2c 02 de 69 06 28 02 00 00 06 28 01 00 00 06 1b 6f 29 00 00 0a 2d 25 06 28 03 00 00 06 } 		$a_01_1 = {07 08 06 08 91 7e 33 00 00 04 08 7e 33 00 00 04 8e 69 5d 91 61 d2 9c 08 17 58 0c 08 06 8e 69 32 df } 		$a_01_2 = {49 4c 6f 76 65 59 6f 75 72 4d 6f 74 68 65 72 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*8+(#a_01_2  & 1)*2) >=20
 
}