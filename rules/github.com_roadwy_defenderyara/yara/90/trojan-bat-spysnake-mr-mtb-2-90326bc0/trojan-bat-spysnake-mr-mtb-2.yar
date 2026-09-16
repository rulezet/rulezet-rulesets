rule Trojan_BAT_SpySnake_MR_MTB_2{
	meta:
		description = "Trojan:BAT/SpySnake.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_01_0 = {0d 00 2b 1f 09 20 e5 8e fb 0e fe 01 13 1a 11 1a 2c 09 20 1c 8f fb 0e 0d 00 2b 08 00 20 01 8f fb 0e 0d 00 } 		$a_03_1 = {50 45 00 00 4c 01 03 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 e0 00 02 01 0b 01 50 } 		$a_01_2 = {53 74 72 52 65 76 65 72 73 65 } 		$a_01_3 = {43 72 65 61 74 65 5f 5f 49 6e 73 74 61 6e 63 65 5f 5f } 	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=16
 
}