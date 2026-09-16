rule TrojanDownloader_Win32_Banload_BGS{
	meta:
		description = "TrojanDownloader:Win32/Banload.BGS,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {2f 61 72 7a 2e 61 64 6b 6a 61 68 33 34 2e 63 6f 6d 2f } 		$a_01_1 = {69 73 74 65 6d 61 2e 6c 6e 6b } 		$a_01_2 = {41 76 69 73 6f 20 64 65 20 53 65 67 75 72 61 6e } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}