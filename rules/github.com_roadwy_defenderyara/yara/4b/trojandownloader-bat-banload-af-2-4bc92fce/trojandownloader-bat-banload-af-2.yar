rule TrojanDownloader_BAT_Banload_AF_2{
	meta:
		description = "TrojanDownloader:BAT/Banload.AF,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {20 e8 03 00 00 20 0f 27 00 00 6f } 		$a_03_1 = {2b 07 1f 64 28 ?? ?? ?? ?? 7e ?? ?? ?? ?? 6f ?? ?? ?? ?? 2d ed } 		$a_00_2 = {2e 00 65 00 78 00 65 00 3f 00 64 00 6c 00 3d 00 31 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}