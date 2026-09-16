rule TrojanDownloader_BAT_Eves_A{
	meta:
		description = "TrojanDownloader:BAT/Eves.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {62 37 32 62 53 49 4c 6c 7a 43 77 58 42 53 72 51 } 		$a_01_1 = {51 69 63 6f 77 49 47 4f 4e 79 64 46 45 76 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}