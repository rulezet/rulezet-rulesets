rule TrojanDownloader_O97M_Qakbot_VAV_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.VAV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 69 73 6b 6e 65 } 		$a_01_1 = {5c 6f 73 6d 77 64 2e 65 78 65 } 		$a_01_2 = {4a 4a 43 43 43 4a 4a } 		$a_01_3 = {52 6f 75 74 } 		$a_01_4 = {65 78 70 6c 6f 72 65 72 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}