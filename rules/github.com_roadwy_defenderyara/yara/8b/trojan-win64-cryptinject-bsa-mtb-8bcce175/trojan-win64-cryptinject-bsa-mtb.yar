rule Trojan_Win64_CryptInject_BSA_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {f2 0f 11 44 24 08 48 83 ec 68 0f b6 05 69 4c 53 01 0f be c0 f2 0f 2a c0 0f b6 05 5a 4c 53 01 } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}