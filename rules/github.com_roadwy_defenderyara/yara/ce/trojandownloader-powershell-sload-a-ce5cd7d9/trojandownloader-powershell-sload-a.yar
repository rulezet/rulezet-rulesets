rule TrojanDownloader_PowerShell_sLoad_A{
	meta:
		description = "TrojanDownloader:PowerShell/sLoad.A,SIGNATURE_TYPE_CMDHSTR_EXT,28 00 28 00 04 00 00 "
		
	strings :
		$a_00_0 = {73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 } 		$a_00_1 = {61 00 70 00 70 00 72 00 75 00 6e 00 4c 00 6f 00 67 00 } 		$a_00_2 = {2e 00 76 00 62 00 73 00 } 		$a_00_3 = {31 00 2c 00 32 00 2c 00 33 00 2c 00 34 00 2c 00 35 00 2c 00 36 00 2c 00 37 00 2c 00 38 00 2c 00 39 00 2c 00 31 00 30 00 2c 00 31 00 31 00 2c 00 31 00 32 00 2c 00 31 00 33 00 2c 00 31 00 34 00 2c 00 31 00 35 00 2c 00 31 00 36 00 } 	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10) >=40
 
}