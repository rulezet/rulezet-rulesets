rule TrojanDownloader_BAT_Balamid_A{
	meta:
		description = "TrojanDownloader:BAT/Balamid.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {77 69 6e 74 61 73 6b 31 36 2e 63 6f 6d } 		$a_80_1 = {5c 6c 73 6d 2e 65 78 65 } 		$a_80_2 = {62 61 67 6c 61 6e 6d 61 64 69 } 		$a_80_3 = {2f 65 78 63 32 2e 74 78 74 } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}