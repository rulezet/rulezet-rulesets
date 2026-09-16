rule Trojan_BAT_Stealer_NITA_MTB{
	meta:
		description = "Trojan:BAT/Stealer.NITA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {02 8e 69 8d 03 00 00 01 0a 16 0b 2b 13 06 07 02 07 91 03 07 03 8e 69 5d 91 61 d2 9c 07 17 58 0b 07 02 8e 69 32 e7 06 2a } 		$a_01_1 = {47 65 74 43 6c 69 70 62 6f 61 72 64 54 65 78 74 } 		$a_01_2 = {47 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}