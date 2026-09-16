rule TrojanDownloader_Win95_NeutrinoEK_gen_G{
	meta:
		description = "TrojanDownloader:Win95/NeutrinoEK.gen!G,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {2f 00 2f 00 42 00 20 00 2f 00 2f 00 45 00 3a 00 4a 00 53 00 63 00 72 00 69 00 70 00 74 00 20 00 [0-02] 33 00 32 00 2e 00 74 00 6d 00 70 00 20 00 22 00 [0-20] 22 00 20 00 22 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-06] 2e 00 [0-06] 2e 00 [0-06] 2e 00 [0-06] 2f 00 3f 00 } 		$a_01_1 = {22 00 4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 2f 00 35 00 2e 00 30 00 20 00 28 00 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}