rule Adware_Win32_AddLyrics{
	meta:
		description = "Adware:Win32/AddLyrics,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {8b 7d 08 8a 14 3e 8b 5d 10 88 14 19 0f be 3c 07 8b c6 6a 03 99 5b f7 fb 41 47 3b d7 } 		$a_01_1 = {32 55 49 45 49 6e 6a 65 63 74 4c 69 62 57 } 		$a_01_2 = {2e 3f 41 56 3f 24 43 43 6f 6d 41 67 67 4f 62 6a 65 63 74 40 56 43 49 6e 6a 65 63 74 4f 62 6a 65 63 74 40 40 40 41 54 4c 40 40 } 		$a_01_3 = {2e 3f 41 56 43 49 45 49 6e 6a 65 63 74 4d 6f 64 75 6c 65 40 40 } 		$a_01_4 = {49 45 49 6e 6a 65 63 74 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}