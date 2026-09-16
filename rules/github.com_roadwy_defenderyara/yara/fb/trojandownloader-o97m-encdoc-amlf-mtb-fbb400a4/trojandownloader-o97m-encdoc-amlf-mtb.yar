rule TrojanDownloader_O97M_EncDoc_AMLF_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.AMLF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {73 75 62 61 75 74 6f 63 6c 6f 73 65 73 6f 63 69 61 6c 62 6f 74 74 6c 65 6f 6e 65 67 75 79 74 61 67 64 65 62 75 67 70 72 69 6e 74 63 61 6c 6c 76 62 61 73 68 65 6c 6c 73 6f 63 69 61 6c 76 62 6e 6f 72 6d 61 6c 66 6f 63 75 73 65 6e 64 73 75 62 } 		$a_01_1 = {73 75 62 61 75 74 6f 63 6c 6f 73 65 79 6f 75 74 75 62 65 68 61 6b 61 6c 6f 6c 63 6f 6e 74 72 6f 6c 74 69 70 74 65 78 74 64 65 62 75 67 70 72 69 6e 74 63 61 6c 6c 76 62 61 73 68 65 6c 6c 79 6f 75 74 75 62 65 76 62 6e 6f 72 6d 61 6c 66 6f 63 75 73 65 6e 64 73 75 62 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}