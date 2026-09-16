rule Trojan_Win32_Truebot_A{
	meta:
		description = "Trojan:Win32/Truebot.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {57 6a 4c ff d6 8b d8 6a 4d 89 5d d4 ff d6 6a 4e 89 45 e8 ff d6 8b f8 6a 4f 89 7d d0 ff d6 } 		$a_01_1 = {5c 5c 2e 5c 70 69 70 65 5c 7b 37 33 46 37 39 37 35 41 2d 41 34 41 32 2d 34 41 42 36 2d 39 31 32 31 2d 41 45 43 41 45 36 38 41 41 42 42 42 7d } 		$a_01_2 = {5c 53 63 72 65 65 6e 4d 6f 6e 69 74 6f 72 53 65 72 76 69 63 65 5c } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}