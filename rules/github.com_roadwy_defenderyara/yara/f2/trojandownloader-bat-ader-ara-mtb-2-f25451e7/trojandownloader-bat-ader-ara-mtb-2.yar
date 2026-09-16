rule TrojanDownloader_BAT_Ader_ARA_MTB_2{
	meta:
		description = "TrojanDownloader:BAT/Ader.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 09 06 09 8e 69 5d 91 08 06 91 61 d2 6f ?? ?? ?? 0a 06 17 58 0a 06 08 8e 69 32 e2 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}