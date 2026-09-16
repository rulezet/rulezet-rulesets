rule Trojan_BAT_Lazy_ALY_MTB{
	meta:
		description = "Trojan:BAT/Lazy.ALY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {0b 16 0c 2b 28 07 08 9a 0d 09 6f 85 00 00 0a 1c 33 17 09 6f 86 00 00 0a 17 33 0e 09 6f 87 00 00 0a 6f 1e 00 00 0a 0a 2b 0a 08 17 58 0c 08 07 8e 69 32 d2 } 		$a_01_1 = {4d 65 72 74 5c 44 65 73 6b 74 6f 70 5c 44 69 73 63 6f 72 64 54 65 6c 65 67 72 61 6d 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 44 69 73 63 6f 72 64 54 65 6c 65 67 72 61 6d 2e 70 64 62 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}