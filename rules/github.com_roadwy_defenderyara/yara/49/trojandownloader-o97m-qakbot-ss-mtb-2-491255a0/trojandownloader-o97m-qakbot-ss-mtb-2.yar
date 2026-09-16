rule TrojanDownloader_O97M_Qakbot_SS_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 63 68 69 6e 61 2e 61 73 69 61 73 70 61 69 6e 2e 63 6f 6d 2f 74 65 72 74 67 65 76 2f } 		$a_01_1 = {43 3a 5c 54 65 73 74 5c 74 65 73 74 32 5c 46 69 6b 73 61 74 2e 65 78 65 } 		$a_01_2 = {31 32 34 37 30 31 35 2e 70 6e 67 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}