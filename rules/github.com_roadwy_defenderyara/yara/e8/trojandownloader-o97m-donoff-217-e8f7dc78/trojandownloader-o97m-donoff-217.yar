rule TrojanDownloader_O97M_Donoff_217{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 61 63 74 75 73 72 65 66 75 73 65 } 		$a_01_1 = {70 69 67 65 6f 6e 75 6e 76 65 69 6c } 		$a_01_2 = {61 72 6d 6f 72 6c 69 67 68 74 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}