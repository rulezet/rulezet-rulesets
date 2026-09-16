rule TrojanDownloader_Win32_Zlob_KDA_dll{
	meta:
		description = "TrojanDownloader:Win32/Zlob.KDA!dll,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {36 35 43 41 38 44 30 35 } 		$a_01_1 = {2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } 		$a_01_2 = {56 43 32 30 58 } 		$a_00_3 = {6c 6f 72 65 72 2e } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}