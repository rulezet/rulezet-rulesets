rule TrojanDownloader_Win32_Banload_ASZ_2{
	meta:
		description = "TrojanDownloader:Win32/Banload.ASZ,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 08 00 00 "
		
	strings :
		$a_01_0 = {33 db 8a 5c 30 ff 33 5d e8 3b fb 7c 0a 81 c3 ff 00 00 00 2b df eb 02 2b df 8d 45 d4 8b d3 } 		$a_00_1 = {2e 62 61 74 00 00 00 00 ff ff ff ff 02 00 00 00 3a 31 00 00 ff ff ff ff 0a 00 00 00 65 72 61 73 65 20 22 25 73 22 } 		$a_00_2 = {49 66 20 65 78 69 73 74 20 22 25 73 22 20 47 6f 74 6f 20 31 } 		$a_00_3 = {69 65 28 61 6c 28 22 25 73 22 2c 34 29 2c 22 61 6c 28 5c 22 25 30 3a 73 5c 22 2c 33 29 22 2c 22 6a 6b 28 5c 22 25 31 3a 73 5c 22 2c 5c 22 25 30 3a 73 5c 22 29 22 29 } 		$a_01_4 = {7b 44 45 4c 45 54 45 7d } 		$a_01_5 = {7b 50 47 44 4e 7d } 		$a_01_6 = {7b 44 4f 57 4e 7d } 		$a_01_7 = {7b 42 4b 53 50 7d } 	condition:
		((#a_01_0  & 1)*5+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=11
 
}