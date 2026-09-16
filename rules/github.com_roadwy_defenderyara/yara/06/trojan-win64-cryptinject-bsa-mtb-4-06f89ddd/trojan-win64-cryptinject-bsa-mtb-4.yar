rule Trojan_Win64_CryptInject_BSA_MTB_4{
	meta:
		description = "Trojan:Win64/CryptInject.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 02 00 00 "
		
	strings :
		$a_03_0 = {eb 21 48 8b 45 e8 48 3b 45 e0 75 09 c7 45 f0 ?? ?? ?? ?? eb 45 b9 e8 03 00 00 48 8b 05 be 40 29 00 ff d0 48 8b 05 ?? ?? ?? ?? 48 89 45 c8 } 		$a_03_1 = {f0 48 0f b1 0a 48 89 45 e8 48 83 7d e8 ?? 75 a8 48 8b 05 ?? ?? ?? ?? 8b 00 83 f8 01 } 	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*2) >=12
 
}