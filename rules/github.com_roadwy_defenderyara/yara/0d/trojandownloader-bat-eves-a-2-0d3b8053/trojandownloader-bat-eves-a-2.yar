rule TrojanDownloader_BAT_Eves_A_2{
	meta:
		description = "TrojanDownloader:BAT/Eves.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {49 00 73 00 61 00 73 00 73 00 33 00 32 00 33 00 2e 00 65 00 78 00 65 00 } 		$a_02_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 31 00 39 00 38 00 2e 00 35 00 30 00 2e 00 31 00 35 00 39 00 2e 00 31 00 35 00 35 00 2f 00 [0-06] 2f 00 [0-05] 2e 00 65 00 78 00 65 00 } 	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}