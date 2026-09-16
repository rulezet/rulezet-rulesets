rule TrojanClicker_Win32_Clikug_A{
	meta:
		description = "TrojanClicker:Win32/Clikug.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {47 6c 6f 62 61 6c 5c 47 43 5f 43 6f 6e 74 72 6f 6c 6c 65 72 00 } 		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 47 69 67 61 43 6c 69 63 6b 73 20 43 72 61 77 6c 65 72 } 		$a_01_2 = {43 68 72 6f 6d 65 20 57 6f 72 6b 65 72 20 46 61 69 6c 65 64 2c 20 25 73 } 		$a_01_3 = {43 6c 69 63 6b 20 54 6f 20 78 3a 20 25 64 20 79 3a 20 25 64 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}