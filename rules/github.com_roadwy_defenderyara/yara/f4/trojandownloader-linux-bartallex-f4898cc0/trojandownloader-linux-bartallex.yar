rule TrojanDownloader_Linux_Bartallex{
	meta:
		description = "TrojanDownloader:Linux/Bartallex,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {61 48 52 30 63 44 6f 76 4c 33 56 74 61 57 4e 76 62 6e 52 79 62 32 77 75 59 32 39 74 4c 6d 4a 79 4c 32 52 76 59 33 4d 76 ?? ?? ?? ?? ?? 53 35 6c 65 47 55 3d } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}