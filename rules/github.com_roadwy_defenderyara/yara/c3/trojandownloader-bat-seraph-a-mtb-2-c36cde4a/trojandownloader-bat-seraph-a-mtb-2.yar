rule TrojanDownloader_BAT_Seraph_A_MTB_2{
	meta:
		description = "TrojanDownloader:BAT/Seraph.A!MTB,SIGNATURE_TYPE_PEHSTR,0d 00 0d 00 02 00 00 "
		
	strings :
		$a_01_0 = {06 1d 19 28 08 00 00 06 0a 06 19 16 28 08 00 00 06 0a 2b 22 0a 2b dc 0a 2b e6 72 01 00 00 70 06 28 06 00 00 06 8c 0d 00 00 01 28 15 00 00 0a 06 28 07 00 00 06 0a 06 28 09 00 00 06 16 fe 01 0b 07 2d d7 } 		$a_01_1 = {fa 01 33 00 16 00 00 01 00 00 00 33 00 00 00 05 00 00 00 08 00 00 00 13 00 00 00 0b } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*3) >=13
 
}