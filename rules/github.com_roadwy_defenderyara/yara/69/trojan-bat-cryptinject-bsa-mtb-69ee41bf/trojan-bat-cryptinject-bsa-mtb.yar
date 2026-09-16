rule Trojan_BAT_CryptInject_BSA_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1d 00 1d 00 03 00 00 "
		
	strings :
		$a_01_0 = {57 9d a2 1d 09 0e 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 37 00 00 00 12 00 } 		$a_01_1 = {48 61 6c 6c 61 6a 2e 50 72 6f 70 65 72 74 69 65 73 } 		$a_01_2 = {6c 6f 76 65 72 2e 65 78 65 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*9) >=29
 
}