rule Trojan_Win64_CryptInject_DA_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 5c 24 08 57 48 83 ec 20 48 63 da 48 8b f9 ba 01 00 00 00 48 8b cb ff 15 ?? ?? ?? ?? 33 d2 48 3b da 7e ?? 8a 0c 97 80 f1 4b 88 0c 02 48 ff c2 48 3b d3 7c } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}