rule Trojan_Win64_CryptInject_BSA_MTB_3{
	meta:
		description = "Trojan:Win64/CryptInject.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {79 6f 75 20 63 6c 69 63 6b 65 64 20 61 20 61 64 64 72 65 73 73 } 		$a_01_1 = {79 6f 75 20 63 6c 69 63 6b 65 64 20 61 20 62 75 73 20 73 74 61 74 69 6f 6e 21 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}