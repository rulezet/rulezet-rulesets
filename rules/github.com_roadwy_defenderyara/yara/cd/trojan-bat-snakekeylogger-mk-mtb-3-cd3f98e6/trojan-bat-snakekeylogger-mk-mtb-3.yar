rule Trojan_BAT_SnakeKeylogger_MK_MTB_3{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 "
		
	strings :
		$a_01_0 = {0d 09 07 16 07 8e 69 6f 0d 00 00 0a 13 04 28 06 00 00 0a 11 04 6f 0e 00 00 0a 13 05 dd 0d 00 00 00 26 7e 0f 00 00 0a 13 05 dd } 		$a_01_1 = {45 00 78 00 70 00 61 00 6e 00 73 00 69 00 6f 00 6e 00 5f 00 4d 00 61 00 6e 00 61 00 67 00 65 00 72 00 5f 00 57 00 61 00 6e 00 69 00 75 00 72 00 2e 00 65 00 78 00 65 00 } 		$a_01_2 = {54 00 54 00 52 00 44 00 5a 00 42 00 57 00 49 00 69 00 6d 00 6a 00 4a 00 5a 00 72 00 47 00 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=9
 
}