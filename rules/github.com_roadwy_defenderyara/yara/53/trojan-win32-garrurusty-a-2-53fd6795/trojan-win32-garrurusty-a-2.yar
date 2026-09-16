rule Trojan_Win32_Garrurusty_A_2{
	meta:
		description = "Trojan:Win32/Garrurusty.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {0c ff 2a 04 29 88 04 3a 8d 04 1a 99 f7 fe 41 3b ce 7c ed } 		$a_01_1 = {70 00 69 00 70 00 65 00 5c 00 4e 00 61 00 6e 00 6e 00 65 00 64 00 50 00 69 00 70 00 65 00 } 		$a_01_2 = {68 20 bf 02 00 ff d7 83 fe 08 74 27 83 fe 05 74 22 83 fe 06 74 1d 83 fe 07 74 18 83 fe 04 75 e0 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}