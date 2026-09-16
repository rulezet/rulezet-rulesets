rule Trojan_BAT_ClipBanker_AYB_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.AYB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_01_0 = {02 07 8f 48 00 00 01 25 47 06 07 06 8e 69 5d 91 61 d2 52 07 17 58 0b 07 02 8e 69 32 e3 } 		$a_01_1 = {73 74 75 62 2e 70 64 62 } 		$a_01_2 = {58 6f 72 45 6e 63 72 79 70 74 4d 79 4b 65 79 } 		$a_01_3 = {47 65 74 52 61 6e 64 6f 6d 4c 65 67 69 74 69 6d 61 74 65 54 61 73 6b 4e 61 6d 65 } 	condition:
		((#a_01_0  & 1)*8+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=12
 
}