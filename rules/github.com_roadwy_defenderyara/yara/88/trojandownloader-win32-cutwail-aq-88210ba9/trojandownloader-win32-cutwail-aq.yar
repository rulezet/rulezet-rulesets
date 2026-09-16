rule TrojanDownloader_Win32_Cutwail_AQ{
	meta:
		description = "TrojanDownloader:Win32/Cutwail.AQ,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff d0 64 a1 30 00 00 00 8f 40 08 b8 ?? ?? ?? ?? 05 ?? ?? ?? ?? 2d } 		$a_03_1 = {c6 03 8b ff 25 90 09 18 00 0f b6 1b 81 f3 ?? ?? ?? ?? 90 90 81 fb ?? ?? ?? ?? 75 09 8b 1d } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}