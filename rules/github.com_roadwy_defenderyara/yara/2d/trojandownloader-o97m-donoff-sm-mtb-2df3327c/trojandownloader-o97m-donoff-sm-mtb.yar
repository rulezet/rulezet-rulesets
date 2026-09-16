rule TrojanDownloader_O97M_Donoff_SM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.SM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 60 70 73 3a 2f 2f 76 65 72 73 37 37 38 76 65 32 39 2e 63 6f 6d 2f 70 65 74 61 6c 6f 2e 6a 60 70 67 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}