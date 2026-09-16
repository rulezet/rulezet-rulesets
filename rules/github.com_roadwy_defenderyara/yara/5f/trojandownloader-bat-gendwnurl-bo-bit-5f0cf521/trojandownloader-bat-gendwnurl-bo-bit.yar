rule TrojanDownloader_BAT_Gendwnurl_BO_bit{
	meta:
		description = "TrojanDownloader:BAT/Gendwnurl.BO!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {68 00 74 00 74 00 70 00 3a 00 [0-20] 2e 00 70 00 77 00 2f 00 69 00 70 00 32 00 2e 00 70 00 68 00 70 00 3f 00 65 00 78 00 3d 00 } 		$a_01_1 = {53 00 74 00 65 00 61 00 6d 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 2e 00 65 00 78 00 65 00 } 		$a_01_2 = {39 00 32 00 33 00 66 00 33 00 32 00 39 00 79 00 66 00 39 00 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}