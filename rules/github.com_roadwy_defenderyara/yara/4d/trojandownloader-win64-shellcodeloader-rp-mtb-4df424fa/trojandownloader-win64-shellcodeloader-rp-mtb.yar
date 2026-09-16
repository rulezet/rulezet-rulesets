rule TrojanDownloader_Win64_ShellcodeLoader_RP_MTB{
	meta:
		description = "TrojanDownloader:Win64/ShellcodeLoader.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {68 00 75 00 6f 00 72 00 6f 00 6e 00 67 00 71 00 6e 00 6d 00 6c 00 62 00 } 		$a_01_1 = {68 00 75 00 6f 00 72 00 6f 00 6e 00 67 00 } 		$a_01_2 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 57 } 		$a_01_3 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 57 } 		$a_01_4 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}