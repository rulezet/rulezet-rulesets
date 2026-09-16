rule TrojanDownloader_Win32_Adload_DU_bit{
	meta:
		description = "TrojanDownloader:Win32/Adload.DU!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {fd 9a 80 5c 49 4e 65 74 43 2e 64 6c 6c 00 2f 45 4e 44 00 68 74 74 70 3a 2f 2f 77 77 77 2e 70 61 70 61 70 69 6e 67 2e 63 6f 6d } 		$a_01_1 = {00 2f 75 73 65 72 61 67 65 6e 74 00 2f 4e 4f 50 52 4f 58 59 00 67 65 74 00 4f 4b 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}