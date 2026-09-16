rule Trojan_Win64_CryptInject_BSA_MTB_5{
	meta:
		description = "Trojan:Win64/CryptInject.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 2b e0 48 8b 05 ?? ?? ?? ?? 48 33 c4 48 89 84 24 e0 20 00 00 41 b9 0f 0f 05 00 4c 8b 84 24 ?? ?? ?? ?? 48 8d 94 24 ?? ?? ?? ?? 48 8d 8c 24 } 		$a_01_1 = {48 8d 84 08 94 0a 00 00 89 44 24 5c c7 44 24 20 00 00 00 00 48 8d 94 24 68 02 00 00 48 8d 4c 24 30 } 	condition:
		((#a_03_0  & 1)*11+(#a_01_1  & 1)*10) >=21
 
}