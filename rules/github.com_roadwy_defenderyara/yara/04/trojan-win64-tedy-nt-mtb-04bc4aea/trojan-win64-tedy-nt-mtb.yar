rule Trojan_Win64_Tedy_NT_MTB{
	meta:
		description = "Trojan:Win64/Tedy.NT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {e8 2e 62 00 00 44 8b cb 4c 8b c0 33 d2 48 8d 0d ?? ?? ?? ?? e8 aa e8 ff ff } 		$a_03_1 = {e8 0a 31 00 00 e8 0d 31 00 00 48 8d 2d ?? ?? ?? ?? 48 8d 15 55 00 02 00 41 b8 00 10 00 00 48 89 e9 } 	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}