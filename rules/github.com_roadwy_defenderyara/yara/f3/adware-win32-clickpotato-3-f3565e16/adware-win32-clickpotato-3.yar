rule Adware_Win32_ClickPotato_3{
	meta:
		description = "Adware:Win32/ClickPotato,SIGNATURE_TYPE_PEHSTR_EXT,09 00 07 00 05 00 00 "
		
	strings :
		$a_02_0 = {43 6c 69 63 6b 50 6f 74 61 74 6f [0-05] 53 41 48 6f 6f 6b 2e 64 6c 6c } 		$a_00_1 = {48 4f 4f 4b 5f 44 4c 4c 3a 20 41 44 20 70 72 6f 63 65 73 73 20 49 44 20 28 30 78 25 30 38 58 29 20 65 71 75 61 6c 73 } 		$a_00_2 = {48 4f 4f 4b 5f 44 4c 4c 3a 20 48 69 64 65 20 41 64 } 		$a_00_3 = {65 6e 61 62 6c 65 5f 74 73 5f 6c 6f 67 67 69 6e 67 } 		$a_00_4 = {53 6f 66 74 77 61 72 65 5c 5a 61 6e 67 6f } 	condition:
		((#a_02_0  & 1)*5+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=7
 
}