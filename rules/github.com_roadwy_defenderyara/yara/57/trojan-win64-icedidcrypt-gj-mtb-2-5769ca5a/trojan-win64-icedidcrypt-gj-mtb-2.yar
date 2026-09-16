rule Trojan_Win64_Icedidcrypt_GJ_MTB_2{
	meta:
		description = "Trojan:Win64/Icedidcrypt.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_02_0 = {8a 00 48 8b 8c 24 ?? ?? ?? ?? 88 01 8a 44 24 ?? 44 89 6c 24 ?? 44 89 6c 24 ?? 0f 57 c0 f2 0f 2a 44 24 ?? f2 0f 11 44 24 ?? 48 8b ac 24 ?? ?? ?? ?? 48 ff c5 8a 44 24 ?? 44 89 6c 24 ?? 44 89 6c 24 ?? 0f 57 c0 } 		$a_02_1 = {49 ff c6 8a 44 24 ?? 44 89 6c 24 ?? 44 89 6c 24 ?? 0f 57 c0 f2 0f 2a 44 24 ?? f2 0f 11 44 24 ?? 8b 84 24 ?? ?? ?? ?? 89 44 24 ?? b8 ?? ?? ?? ?? 44 8b 64 24 ?? e9 } 		$a_80_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } 	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_80_2  & 1)*10) >=30
 
}