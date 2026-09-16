rule TrojanDownloader_O97M_Powdow_EM_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.EM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {68 74 74 70 3a 2f 2f 6f 77 65 6e 74 69 2e 63 6f 6d 2f [0-10] 2e 65 78 65 } 		$a_01_1 = {43 3a 5c 44 58 63 6b 61 47 50 5c 50 4f 53 70 77 45 69 5c 75 75 4c 4f 52 4a 68 2e 65 78 65 } 		$a_01_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}