rule Ransom_Win32_Tobfy_S{
	meta:
		description = "Ransom:Win32/Tobfy.S,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {70 69 63 74 75 72 65 2e 70 68 70 3f 70 69 6e 3d } 		$a_01_1 = {2f 68 63 79 62 6e 71 2f 76 7a 74 2e 77 63 74 } 		$a_01_2 = {67 6e 66 78 7a 74 65 2e 72 6b 72 } 		$a_00_3 = {0f be 02 85 c0 74 62 8b 4d 08 0f be 11 83 fa 61 7c 26 8b 45 08 0f be 08 83 f9 7a 7f 1b 8b 55 08 0f be 02 83 e8 54 99 b9 1a 00 00 00 f7 f9 83 c2 61 8b 45 08 88 10 } 		$a_00_4 = {8a 01 3c 61 7c 15 3c 7a 7f 11 0f be c0 83 e8 54 6a 1a 99 5f f7 ff 80 c2 61 eb 17 3c 41 7c 15 3c 5a 7f 11 0f be c0 83 e8 34 6a 1a 99 5f f7 ff 80 c2 41 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=3
 
}