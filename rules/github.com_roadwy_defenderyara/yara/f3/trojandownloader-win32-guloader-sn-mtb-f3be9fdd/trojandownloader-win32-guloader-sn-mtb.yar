rule TrojanDownloader_Win32_GuLoader_SN_MTB{
	meta:
		description = "TrojanDownloader:Win32/GuLoader.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 07 00 00 "
		
	strings :
		$a_01_0 = {58 79 6c 6f 67 72 61 } 		$a_01_1 = {4e 6f 76 69 63 65 68 6f 6f } 		$a_01_2 = {4f 75 74 72 61 6e 67 } 		$a_01_3 = {42 6f 63 65 6d 65 6e 6e 65 } 		$a_01_4 = {57 49 45 4e 45 52 4e 45 53 } 		$a_01_5 = {4b 76 69 64 69 73 } 		$a_01_6 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*20) >=25
 
}