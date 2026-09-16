rule TrojanDownloader_Win32_Dofoil_AU{
	meta:
		description = "TrojanDownloader:Win32/Dofoil.AU,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {e8 e7 df 00 00 83 c4 04 68 1a 04 00 00 ff d7 6a 00 e8 e9 dc 00 00 } 		$a_01_1 = {6a 00 68 df e2 f0 01 e8 4e fb ff ff } 		$a_01_2 = {48 00 65 00 6c 00 6c 00 53 00 74 00 61 00 72 00 2e 00 65 00 78 00 65 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}