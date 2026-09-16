rule Trojan_Win64_Icedidcrypt_GJ_MTB{
	meta:
		description = "Trojan:Win64/Icedidcrypt.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_02_0 = {89 d3 30 c3 bb ?? ?? ?? ?? 41 0f 45 dd 84 c0 89 d8 41 0f 45 c5 84 d2 0f 44 c3 eb } 		$a_00_1 = {8d 48 ff 0f af c8 44 31 e1 83 c9 fe 44 39 e1 0f 94 c0 83 fa 0a 0f 9c c3 30 c3 } 		$a_80_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } 	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*10+(#a_80_2  & 1)*10) >=30
 
}