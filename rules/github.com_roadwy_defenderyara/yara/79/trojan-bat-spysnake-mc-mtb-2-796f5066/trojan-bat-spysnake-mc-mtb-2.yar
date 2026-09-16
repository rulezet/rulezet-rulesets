rule Trojan_BAT_SpySnake_MC_MTB_2{
	meta:
		description = "Trojan:BAT/SpySnake.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_03_0 = {07 06 11 08 9a 1f 10 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 11 08 17 58 13 08 20 ?? ?? ?? 9e 38 ?? ?? ?? ff } 		$a_01_1 = {50 72 69 73 6f 6e 65 72 4d 61 6e 61 67 65 6d 65 6e 74 53 79 73 74 65 6d 5f 2e 50 72 6f 70 65 72 74 69 65 73 } 		$a_01_2 = {65 6d 70 6c 6f 79 65 65 43 6f 6e 74 72 6f 6c 31 5f 4c 6f 61 64 } 		$a_01_3 = {70 72 69 73 6f 6e 65 72 43 6f 6e 74 72 6f 6c 31 5f 4c 6f 61 64 } 	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=16
 
}