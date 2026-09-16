rule Trojan_Win64_CryptInject_BSA_MTB_6{
	meta:
		description = "Trojan:Win64/CryptInject.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 06 00 00 "
		
	strings :
		$a_01_0 = {6d 61 74 72 69 78 31 2e 74 78 74 } 		$a_01_1 = {72 65 73 75 6c 74 5f 6d 61 74 72 69 78 2e 74 78 74 } 		$a_01_2 = {41 b9 0a 00 00 00 42 f6 44 f0 38 48 74 79 42 8a 44 f0 3a 41 3a c1 74 6f 85 ed } 		$a_01_3 = {4b 8b 04 c3 42 8a 4c f0 3b 41 3a c9 74 45 85 ed 74 41 41 88 0f 41 8d 79 f8 4b } 		$a_01_4 = {3c 41 3a c9 74 19 85 ed 74 15 41 88 0f 41 8d 79 f9 4b 8b 04 c3 4c 03 fa ff cd } 		$a_01_5 = {46 88 4c f0 3c 41 8b cd e8 92 76 00 00 85 c0 } 	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=16
 
}