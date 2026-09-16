rule Trojan_Win64_CryptInject_AY_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.AY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4d 54 55 33 4c 6a 49 30 4e 53 34 79 4e 44 51 75 4e 6a 63 3d } 		$a_01_1 = {70 6f 72 74 70 6f 72 74 70 6f 72 74 } 		$a_01_2 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 25 73 2c 20 72 75 6e } 		$a_01_3 = {53 54 41 47 45 31 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}