rule TrojanDownloader_O97M_Emotet_RA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.RA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_03_0 = {5c 73 6f 61 6d ?? 2e 4f 43 58 } 		$a_03_1 = {5c 73 6f 61 6d ?? 2e 6f 63 78 } 		$a_01_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } 		$a_01_3 = {75 72 6c 6d 6f 6e } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5) >=11
 
}