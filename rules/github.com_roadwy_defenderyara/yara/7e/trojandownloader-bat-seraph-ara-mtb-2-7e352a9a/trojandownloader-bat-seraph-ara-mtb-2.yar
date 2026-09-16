rule TrojanDownloader_BAT_Seraph_ARA_MTB_2{
	meta:
		description = "TrojanDownloader:BAT/Seraph.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {13 04 16 13 05 16 2d 15 2b 19 11 04 11 05 09 11 05 09 8e 69 5d 91 07 11 05 91 61 d2 9c 11 05 17 58 13 05 11 05 15 2c d3 16 2d f4 07 8e 69 32 da 11 04 13 06 de 65 28 } 		$a_01_1 = {48 74 74 70 57 65 62 52 65 71 75 65 73 74 } 		$a_01_2 = {57 65 62 52 65 73 70 6f 6e 73 65 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}