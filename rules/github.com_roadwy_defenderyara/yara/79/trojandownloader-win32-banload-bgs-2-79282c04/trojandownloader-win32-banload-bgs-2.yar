rule TrojanDownloader_Win32_Banload_BGS_2{
	meta:
		description = "TrojanDownloader:Win32/Banload.BGS,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {4d 00 6f 00 30 00 30 00 34 00 35 00 39 00 34 00 36 00 } 		$a_01_1 = {4c 49 53 54 41 4f 53 50 4f 52 52 41 44 45 41 52 51 55 49 56 4f 53 } 		$a_01_2 = {2e 00 70 00 69 00 67 00 } 		$a_01_3 = {69 00 6e 00 64 00 79 00 73 00 6f 00 63 00 6b 00 65 00 74 00 73 00 } 		$a_01_4 = {03 04 9e 03 84 9d f0 fb ff ff 25 ff 00 00 80 79 07 48 0d 00 ff ff ff 40 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*3) >=10
 
}