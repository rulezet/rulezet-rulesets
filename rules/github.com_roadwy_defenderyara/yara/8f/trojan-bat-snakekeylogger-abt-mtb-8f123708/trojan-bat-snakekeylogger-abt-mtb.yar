rule Trojan_BAT_SnakeKeylogger_ABT_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.ABT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 05 00 00 "
		
	strings :
		$a_03_0 = {07 09 16 11 04 2b 15 08 09 16 09 8e 69 6f ?? ?? ?? 0a 25 13 04 16 30 02 2b 09 2b e4 6f ?? ?? ?? 0a 2b e4 07 6f ?? ?? ?? 0a 13 05 de 17 } 		$a_03_1 = {72 33 00 00 70 28 ?? ?? ?? 06 28 ?? ?? ?? 06 2a } 		$a_01_2 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } 		$a_01_3 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } 		$a_01_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } 	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*4+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=11
 
}