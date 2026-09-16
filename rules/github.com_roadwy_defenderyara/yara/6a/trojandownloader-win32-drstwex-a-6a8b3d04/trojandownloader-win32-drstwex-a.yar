rule TrojanDownloader_Win32_Drstwex_A{
	meta:
		description = "TrojanDownloader:Win32/Drstwex.A,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 53 05 75 0d 00 00 81 e8 01 00 00 00 c1 e3 02 } 		$a_01_1 = {50 53 05 75 0d 00 00 48 c1 e3 02 } 		$a_01_2 = {90 90 8a 1e 90 90 90 32 d8 90 88 1e } 		$a_01_3 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } 		$a_01_4 = {43 72 65 61 74 65 54 68 72 65 61 64 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5) >=16
 
}