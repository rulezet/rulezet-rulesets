rule Trojan_Win32_Vidar_MD_MTB_3{
	meta:
		description = "Trojan:Win32/Vidar.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {06 c8 76 d4 96 80 e2 15 69 87 ac da 47 b3 03 c6 54 69 11 ef 63 69 b9 ea 6c fb ce a6 fb dd 92 af 55 47 33 c6 26 e2 58 fc 5b bb ad d1 48 f0 98 e3 } 		$a_01_1 = {d0 21 fe a6 5d ea f4 64 16 eb ba 9b 19 0d ba c2 73 e1 c5 99 2e 4c c2 9c 13 39 93 b7 29 21 05 a4 36 ea 28 a3 2b eb d4 b1 19 f3 10 c1 1e 05 cd 64 } 		$a_01_2 = {e0 00 02 01 0b 01 50 00 00 b6 0f 00 00 54 03 00 00 00 00 00 e0 92 4e 00 00 20 } 		$a_01_3 = {e0 00 02 01 0b 01 50 00 00 32 10 00 00 20 01 00 00 00 00 00 b8 4d 4b 00 00 20 } 		$a_01_4 = {2e 74 68 65 6d 69 64 61 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1) >=8
 
}