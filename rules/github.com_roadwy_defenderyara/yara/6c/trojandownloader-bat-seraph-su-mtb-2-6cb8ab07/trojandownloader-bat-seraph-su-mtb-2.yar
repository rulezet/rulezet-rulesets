rule TrojanDownloader_BAT_Seraph_SU_MTB_2{
	meta:
		description = "TrojanDownloader:BAT/Seraph.SU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 05 72 8d 00 00 70 6f 0d 00 00 0a 6f 0e 00 00 0a 6f 0f 00 00 0a 6f 10 00 00 0a 6f 11 00 00 0a 13 04 dd 0f 00 00 00 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}