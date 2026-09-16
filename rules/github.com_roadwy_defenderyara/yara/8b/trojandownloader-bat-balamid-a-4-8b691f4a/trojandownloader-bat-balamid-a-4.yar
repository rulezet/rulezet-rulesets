rule TrojanDownloader_BAT_Balamid_A_4{
	meta:
		description = "TrojanDownloader:BAT/Balamid.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {77 77 77 2e 77 69 6e 74 61 73 6b 90 0f 02 00 2e 63 6f 6d } 		$a_02_1 = {77 00 77 00 77 00 2e 00 77 00 69 00 6e 00 74 00 61 00 73 00 6b 00 90 0f 01 00 00 90 0f 01 00 00 2e 00 63 00 6f 00 6d 00 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}