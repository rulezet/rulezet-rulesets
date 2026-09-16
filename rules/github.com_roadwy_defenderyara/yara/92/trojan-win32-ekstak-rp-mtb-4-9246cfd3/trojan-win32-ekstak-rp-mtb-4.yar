rule Trojan_Win32_Ekstak_RP_MTB_4{
	meta:
		description = "Trojan:Win32/Ekstak.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {d9 45 08 d8 c8 d9 05 38 84 56 00 d8 4d 08 d8 05 3c 84 56 00 de c9 d8 05 40 84 56 00 d8 0d 44 84 56 00 d9 5d fc 9b eb 3b d9 45 08 d8 1d 40 84 56 00 9b df e0 9e 73 27 d9 05 48 84 } 		$a_01_1 = {74 2e 8a 06 46 8a 27 47 38 c4 74 f2 2c 41 3c 1a 1a c9 80 e1 20 02 c1 04 41 86 e0 2c 41 3c 1a 1a c9 80 e1 20 02 c1 04 41 38 e0 74 d2 1a c0 1c ff 0f be c0 eb 78 } 		$a_01_2 = {65 00 53 00 49 00 4d 00 20 00 43 00 6c 00 69 00 65 00 6e 00 74 00 2e 00 65 00 78 00 65 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}