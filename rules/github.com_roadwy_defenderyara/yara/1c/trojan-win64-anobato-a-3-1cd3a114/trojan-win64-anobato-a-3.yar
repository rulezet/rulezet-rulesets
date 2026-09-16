rule Trojan_Win64_Anobato_A_3{
	meta:
		description = "Trojan:Win64/Anobato.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {48 83 ec 20 eb 0d 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 00 48 8d 0d ec ff ff ff ff 15 ?? ?? ?? ?? 48 83 c4 20 90 90 } 		$a_01_1 = {48 83 ec 20 48 c7 c1 00 00 00 00 48 c7 c2 00 14 00 00 49 c7 c0 00 30 00 00 49 c7 c1 04 00 00 00 ff d0 } 		$a_01_2 = {eb 06 38 35 2e 39 33 00 } 		$a_01_3 = {eb 06 2e 30 2e 32 32 00 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}