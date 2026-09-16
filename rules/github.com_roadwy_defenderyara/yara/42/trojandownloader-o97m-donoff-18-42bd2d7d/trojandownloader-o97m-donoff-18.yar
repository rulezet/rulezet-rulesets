rule TrojanDownloader_O97M_Donoff_18{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {22 47 45 54 22 2c 20 aa a3 b4 a6 a7 af af b3 b7 be b0 bc a1 be a6 b2 a6 a7 ab a1 a2 bb b2 b8 bc b9 af a5 a4 b9 ba bf a2 ac b5 be b3 b6 ae a8 af } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}