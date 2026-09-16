rule Trojan_BAT_CryptInject_BSA_MTB_3{
	meta:
		description = "Trojan:BAT/CryptInject.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,26 00 26 00 04 00 00 "
		
	strings :
		$a_01_0 = {d0 3b 00 00 01 2b 17 7e 71 00 00 04 20 56 c0 66 06 2b 12 2b 17 2b 1c 2b 1d 2b 22 2b 27 2a } 		$a_01_1 = {2b e2 02 2b e1 28 43 00 00 0a 2b dc 28 01 00 00 2b 2b d7 6f 45 00 00 0a 2b d2 } 		$a_01_2 = {4d 65 6d 62 65 72 52 65 66 73 50 72 6f 78 79 } 		$a_01_3 = {53 6d 61 72 74 41 73 73 65 6d 62 6c 79 2e 48 6f 75 73 65 4f 66 43 61 72 64 73 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*9+(#a_01_3  & 1)*9) >=38
 
}