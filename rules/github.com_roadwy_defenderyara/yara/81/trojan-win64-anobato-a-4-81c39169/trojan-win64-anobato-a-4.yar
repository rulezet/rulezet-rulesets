rule Trojan_Win64_Anobato_A_4{
	meta:
		description = "Trojan:Win64/Anobato.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_03_0 = {41 8b 0f 67 8b 49 04 41 8b 17 01 da 83 c2 0c 67 31 0a 41 3b 87 ?? ?? 00 00 73 08 83 c0 04 83 c3 04 eb e4 } 		$a_01_1 = {49 8b 1f 8b 43 08 83 f8 00 74 07 80 7c 03 ff c3 74 02 eb 26 } 		$a_01_2 = {00 64 48 83 ec 20 48 c7 c1 00 00 00 00 48 c7 c2 00 40 01 00 49 c7 c0 00 30 00 00 49 c7 c1 40 00 00 00 41 ff } 		$a_01_3 = {eb 0f 31 39 33 2e 32 38 2e 31 37 39 2e 31 30 35 00 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}