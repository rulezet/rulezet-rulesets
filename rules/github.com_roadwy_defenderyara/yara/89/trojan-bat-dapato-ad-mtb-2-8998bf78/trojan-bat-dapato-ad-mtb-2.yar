rule Trojan_BAT_Dapato_AD_MTB_2{
	meta:
		description = "Trojan:BAT/Dapato.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 04 11 04 2c 16 00 06 28 ?? 00 00 0a 00 72 ?? 00 00 70 28 ?? 00 00 0a 00 00 2b 0d 00 72 ?? 00 00 70 28 ?? 00 00 0a 00 00 00 de 05 } 		$a_01_1 = {73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 41 6e 79 44 65 73 6b 41 64 64 2e 65 78 65 5c 41 6e 79 44 65 73 6b 41 64 64 2e 65 78 65 5c 6f 62 6a 5c 44 65 62 75 67 5c 41 6e 79 44 65 73 6b 41 64 64 2e 65 78 65 2e 70 64 62 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}