rule TrojanSpy_Win32_OnLineGames{
	meta:
		description = "TrojanSpy:Win32/OnLineGames,SIGNATURE_TYPE_PEHSTR,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_01_0 = {c7 85 14 fe ff ff 5d e4 36 57 c6 85 1c fe ff ff 01 c7 85 20 fe ff ff 68 d8 1a ef } 		$a_01_1 = {5f 21 51 47 55 41 5f 4d 41 48 55 41 21 5f } 		$a_01_2 = {51 47 41 70 70 } 		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 54 65 6e 63 65 6e 74 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=13
 
}