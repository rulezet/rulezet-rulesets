rule TrojanDownloader_Win32_Renos_AW{
	meta:
		description = "TrojanDownloader:Win32/Renos.AW,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {68 69 2c 20 62 6f 74 6e 65 74 20 4a 61 63 6b 20 68 65 72 65 } 		$a_01_1 = {72 69 6f 2e 64 6c 6c 00 44 6c 6c 4d 61 69 6e 00 57 4c 45 76 65 6e 74 53 74 61 72 74 53 68 65 6c 6c } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}