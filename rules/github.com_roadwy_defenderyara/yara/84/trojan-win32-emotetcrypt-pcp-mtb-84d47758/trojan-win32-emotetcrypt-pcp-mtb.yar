rule Trojan_Win32_EmotetCrypt_PCP_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.PCP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_81_0 = {63 3a 5c 55 73 65 72 73 5c 44 4f 44 4f 5c 56 69 64 65 6f 73 5c 54 72 61 6e 73 70 61 72 65 6e 74 43 6f 6e 74 72 6f 6c 5f 73 72 63 5c 54 72 61 6e 73 70 61 72 65 6e 74 43 6f 6e 74 72 6f 6c 5c 52 65 6c 65 61 73 65 5c 54 72 61 6e 73 70 61 72 65 6e 74 43 6f 6e 74 72 6f 6c 2e 70 64 62 } 		$a_81_1 = {43 53 42 68 76 53 57 43 76 46 52 76 66 43 66 41 6f 4a 64 6f 46 75 41 55 6d 4b } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}