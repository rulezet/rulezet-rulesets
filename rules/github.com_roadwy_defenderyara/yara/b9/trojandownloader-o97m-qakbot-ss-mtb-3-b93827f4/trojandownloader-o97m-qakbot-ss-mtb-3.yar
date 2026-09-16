rule TrojanDownloader_O97M_Qakbot_SS_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6f 6e 6c 69 6e 65 2d 63 6f 6d 70 61 6e 69 65 73 68 6f 75 73 65 2e 63 6f 6d 2f 69 74 65 2e 70 6e 67 } 		$a_01_1 = {43 3a 5c 67 6c 69 6d 70 69 5c 64 75 6f 74 2e 70 6f 69 } 		$a_01_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } 		$a_01_3 = {72 75 6e 64 6c 6c 33 32 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}