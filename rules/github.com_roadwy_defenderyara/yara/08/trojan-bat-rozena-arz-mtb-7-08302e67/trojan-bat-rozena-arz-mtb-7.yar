rule Trojan_BAT_Rozena_ARZ_MTB_7{
	meta:
		description = "Trojan:BAT/Rozena.ARZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 13 07 2b 14 07 11 07 8f ?? 00 00 01 25 47 08 61 d2 52 11 07 17 58 13 07 11 07 07 8e 69 32 e5 } 		$a_01_1 = {44 65 73 6b 74 6f 70 5c 63 6f 64 65 5c 45 6e 63 72 79 70 74 69 6f 6e 5c 45 6e 63 72 79 70 74 69 6f 6e 5c 6f 62 6a 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 45 6e 63 72 79 70 74 69 6f 6e 2e 70 64 62 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}