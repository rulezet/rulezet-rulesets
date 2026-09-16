rule Trojan_Win32_Garrurusty_A_4{
	meta:
		description = "Trojan:Win32/Garrurusty.A,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 04 00 00 "
		
	strings :
		$a_01_0 = {0c ff 2a 04 29 88 04 3a 8d 04 1a 99 f7 fe 41 3b ce 7c ed } 		$a_01_1 = {3d 99 00 00 00 0f 84 f2 fa ff ff 3d 9a 00 00 00 0f 84 e7 fa ff ff 3d 85 00 00 00 75 1e } 		$a_01_2 = {57 00 65 00 62 00 4d 00 6f 00 6e 00 65 00 79 00 20 00 4b 00 65 00 65 00 70 00 65 00 72 00 20 00 43 00 6c 00 61 00 73 00 73 00 69 00 63 00 } 		$a_01_3 = {78 69 61 6e 67 79 69 6e 2e 64 79 6e 64 6e 73 2d 77 65 62 2e 63 6f 6d } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=21
 
}