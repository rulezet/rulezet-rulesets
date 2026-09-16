rule TrojanDownloader_O97M_Qakbot_SS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 6f 6e 6c 69 6e 65 63 6f 6d 70 61 6e 69 65 68 6f 75 73 65 2e 63 6f 6d 2f 73 6f 72 76 2e 70 6e 67 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}