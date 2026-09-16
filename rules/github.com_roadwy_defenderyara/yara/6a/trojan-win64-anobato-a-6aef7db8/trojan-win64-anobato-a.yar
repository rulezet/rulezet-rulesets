rule Trojan_Win64_Anobato_A{
	meta:
		description = "Trojan:Win64/Anobato.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 83 ec 08 48 83 ec 20 eb 0a 6e 74 64 6c 6c 2e 64 6c 6c 00 48 8d 0d ef ff ff ff ff 15 ?? ?? ?? ?? 48 83 c4 20 } 		$a_01_1 = {48 05 04 d0 07 00 48 81 be b0 01 00 00 0c 0c 0c 0c 75 09 } 		$a_01_2 = {72 65 67 73 76 72 6d 6f 62 73 79 6e 72 75 6e 64 6c 6c 72 75 6e 6f 6e 63 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2) >=4
 
}