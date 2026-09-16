rule TrojanDownloader_Win32_Cutwail_gen_C{
	meta:
		description = "TrojanDownloader:Win32/Cutwail.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 45 08 64 8b 78 01 33 c0 83 e8 02 c9 c2 04 00 } 		$a_03_1 = {c1 eb 02 8d b7 ?? ?? ?? ?? 8b 14 1e 81 ea ?? ?? ?? ?? 2b fa c2 04 00 cc cc cc cc } 		$a_01_2 = {c3 8d 47 30 8b 04 08 8b 40 0c 8b 40 1c 8b 00 8b 40 08 c3 } 		$a_03_3 = {c1 e2 02 8d 88 ?? ?? ?? ?? 8b 1c 11 03 ca 83 eb 28 8d 95 ?? ?? ?? ?? 03 55 e4 89 1a 83 e9 04 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}