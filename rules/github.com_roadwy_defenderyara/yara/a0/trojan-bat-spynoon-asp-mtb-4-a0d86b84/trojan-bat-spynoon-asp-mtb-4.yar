rule Trojan_BAT_SpyNoon_ASP_MTB_4{
	meta:
		description = "Trojan:BAT/SpyNoon.ASP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0b 16 0c 2b 3b 07 08 9a 0d 00 09 6f ?? 00 00 0a 28 ?? 00 00 0a 16 fe 01 13 04 11 04 2c 1d 00 7e } 		$a_01_1 = {6a 61 6d 65 73 5c 44 65 73 6b 74 6f 70 5c 6b 65 79 6c 6f 67 67 65 72 5c 6b 65 79 6c 6f 67 67 65 72 5c 6f 62 6a 5c 44 65 62 75 67 5c 6b 65 79 6c 6f 67 67 65 72 2e 70 64 62 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}