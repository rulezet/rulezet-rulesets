rule TrojanDownloader_BAT_Seraph_SV_MTB_3{
	meta:
		description = "TrojanDownloader:BAT/Seraph.SV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 08 09 06 09 91 7e 01 00 00 04 59 d2 9c 00 09 17 58 0d 09 06 8e 69 fe 04 13 04 11 04 2d e1 } 		$a_01_1 = {47 6e 66 6f 6a 61 65 71 6a 6c 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}