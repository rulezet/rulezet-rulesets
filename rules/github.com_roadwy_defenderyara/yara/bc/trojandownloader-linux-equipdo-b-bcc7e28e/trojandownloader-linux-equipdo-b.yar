rule TrojanDownloader_Linux_Equipdo_B{
	meta:
		description = "TrojanDownloader:Linux/Equipdo.B,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {43 61 6c 6c 20 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 28 22 68 74 74 70 3a } 		$a_00_1 = {2f 62 69 68 2f 73 73 2e 65 78 65 22 2c 20 22 65 33 65 33 65 33 2e 65 78 65 } 		$a_01_2 = {4d 73 67 42 6f 78 20 22 45 73 74 65 20 64 6f 63 75 6d 65 6e 74 6f 20 6e 6f 20 65 73 20 63 6f 6d 70 61 74 69 62 6c 65 20 63 6f 6e 20 65 73 74 65 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}