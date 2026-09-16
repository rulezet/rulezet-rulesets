rule Trojan_Win64_CryptInject_BSA_MTB_2{
	meta:
		description = "Trojan:Win64/CryptInject.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 61 72 6e 73 2e 64 6c 6c } 		$a_01_1 = {4c 8b 41 10 41 8b 40 38 c1 e8 04 a8 01 75 0b 48 8b d1 49 8b c8 } 		$a_01_2 = {45 33 c0 33 c9 41 8d 50 02 e9 8a ff } 	condition:
		((#a_01_0  & 1)*30+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10) >=50
 
}