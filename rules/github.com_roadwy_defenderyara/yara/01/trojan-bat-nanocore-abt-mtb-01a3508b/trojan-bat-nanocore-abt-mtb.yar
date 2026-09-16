rule Trojan_BAT_Nanocore_ABT_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.ABT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_03_0 = {91 61 d2 6f ?? ?? ?? 0a 07 1d 2c 04 17 58 0b 07 02 8e 69 32 db 06 6f ?? ?? ?? 0a 25 2d 02 26 14 2a } 		$a_01_1 = {57 65 62 52 65 71 75 65 73 74 } 		$a_01_2 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } 		$a_01_3 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } 		$a_01_4 = {47 65 74 54 79 70 65 73 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}