rule Ransom_Win32_Phobos_A_2{
	meta:
		description = "Ransom:Win32/Phobos.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {64 96 3b 24 ee e6 1f 4c 43 6e 30 d5 5b 69 2b 9c f6 de 4a } 		$a_01_1 = {40 b5 d3 93 0e 11 c2 17 ab d7 29 37 40 e4 97 8f b0 7a 02 } 		$a_03_2 = {8d 7d e0 ab ab ab ab 8d ?? ?? 8d ?? ?? 50 8d ?? ?? e8 ?? ?? ?? ?? ff ?? ?? 8b ?? ff ?? ?? 50 e8 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*2) >=3
 
}