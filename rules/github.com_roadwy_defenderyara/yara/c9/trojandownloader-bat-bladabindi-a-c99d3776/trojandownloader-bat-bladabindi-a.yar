rule TrojanDownloader_BAT_Bladabindi_A{
	meta:
		description = "TrojanDownloader:BAT/Bladabindi.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {1d 28 05 00 00 0a 72 ?? 00 00 70 7e 03 00 00 04 72 ?? 00 00 70 28 06 00 00 0a 17 73 0b 00 00 0a 0b 28 0c 00 00 0a 6f 0d 00 00 0a 28 0e 00 00 0a } 		$a_00_1 = {00 6f 6b 2e 65 78 65 00 } 		$a_00_2 = {6c 69 6e 6b 73 20 53 74 61 72 74 55 50 20 68 61 73 68 } 	condition:
		((#a_03_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}