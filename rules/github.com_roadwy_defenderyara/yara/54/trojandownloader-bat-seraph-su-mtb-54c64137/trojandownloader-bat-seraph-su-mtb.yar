rule TrojanDownloader_BAT_Seraph_SU_MTB{
	meta:
		description = "TrojanDownloader:BAT/Seraph.SU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 2b 06 16 2c 0a 26 de 0d 28 ?? ?? ?? 06 2b f3 0c 2b f4 26 de 00 08 2c e7 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}