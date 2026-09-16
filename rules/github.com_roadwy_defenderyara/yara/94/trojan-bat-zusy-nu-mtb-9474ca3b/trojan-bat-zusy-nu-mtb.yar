rule Trojan_BAT_Zusy_NU_MTB{
	meta:
		description = "Trojan:BAT/Zusy.NU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {5d 06 06 1f 1f 5f 64 06 06 1f 1f 5f 64 5b 5d 16 5f 06 06 20 33 97 10 92 06 5c 5a 66 5b 66 41 5b 00 00 00 20 a3 a9 16 b0 06 06 20 79 56 e9 4f 61 61 58 67 } 		$a_01_1 = {06 1f 16 63 66 58 06 65 1f 1f 5f 63 20 a9 e9 86 02 58 67 0a 02 } 		$a_01_2 = {53 00 74 00 65 00 61 00 6c 00 31 00 2e 00 65 00 78 00 65 00 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}