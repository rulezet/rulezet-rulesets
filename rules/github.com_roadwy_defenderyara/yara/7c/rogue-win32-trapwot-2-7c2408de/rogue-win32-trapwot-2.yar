rule Rogue_Win32_Trapwot_2{
	meta:
		description = "Rogue:Win32/Trapwot,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_03_0 = {83 c7 14 80 3f 4d 75 ?? 80 7f 01 5a 75 ?? 3b 5d 08 73 } 		$a_01_1 = {b8 4f ec c4 4e f7 e1 c1 ea 03 6b d2 1a 2b ca 0f be 55 ff 3b ca 75 } 		$a_01_2 = {2f 67 65 74 5f 74 77 6f 2e 70 68 70 3f } 		$a_01_3 = {52 75 6e 49 6e 76 61 6c 69 64 53 69 67 6e 61 74 75 72 65 73 00 00 00 00 43 68 65 63 6b 45 78 65 53 69 67 6e 61 74 75 72 65 73 00 00 6e 6f 00 } 	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}