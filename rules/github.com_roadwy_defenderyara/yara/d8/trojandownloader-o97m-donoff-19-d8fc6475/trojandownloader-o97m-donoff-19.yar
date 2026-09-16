rule TrojanDownloader_O97M_Donoff_19{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 ae a3 b5 a2 a4 a7 b4 b2 bf b6 bc bf bd aa a1 b0 bc bd ab b3 a9 b9 ae b6 ba a9 a5 ab b8 b5 b6 b5 b8 a2 a6 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}