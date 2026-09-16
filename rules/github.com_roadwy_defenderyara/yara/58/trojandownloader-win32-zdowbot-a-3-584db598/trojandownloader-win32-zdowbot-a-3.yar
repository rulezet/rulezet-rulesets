rule TrojanDownloader_Win32_Zdowbot_A_3{
	meta:
		description = "TrojanDownloader:Win32/Zdowbot.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {2f 67 61 74 65 2e 70 68 70 7c 68 74 74 70 3a 2f 2f [0-20] 2e 72 75 2f [0-06] 2f 67 61 74 65 2e 70 68 70 7c 68 74 74 70 3a 2f 2f } 		$a_03_1 = {2f 6c 73 35 2f 66 6f 72 75 6d 2e 70 68 70 7c 68 74 74 70 3a 2f 2f [0-20] 2e 72 75 2f [0-06] 2f 66 6f 72 75 6d 2e 70 68 70 7c 68 74 74 70 3a 2f 2f [0-20] 2e 72 75 2f 90 1b 01 2f 66 6f 72 75 6d 2e 70 68 70 } 		$a_01_2 = {47 55 49 44 3d 25 49 36 34 75 26 42 55 49 4c 44 3d 25 73 26 49 4e 46 4f 3d 25 73 26 49 50 3d 25 73 26 54 59 50 45 3d 31 26 57 49 4e 3d 25 64 2e 25 64 28 25 73 29 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*2) >=3
 
}