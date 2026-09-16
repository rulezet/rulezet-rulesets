rule TrojanDownloader_Win32_Dalexis_F{
	meta:
		description = "TrojanDownloader:Win32/Dalexis.F,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 "
		
	strings :
		$a_01_0 = {83 7c 24 10 00 88 0a 74 05 30 0c 3e eb 03 30 04 3e 47 83 ff 10 75 02 33 ff } 		$a_03_1 = {68 60 ea 00 00 b8 c0 d4 01 00 e8 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 59 50 ff d6 3b df 5b 74 27 6a 0a } 		$a_01_2 = {25 30 38 78 2e 6a 70 67 } 	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*5+(#a_01_2  & 1)*1) >=8
 
}