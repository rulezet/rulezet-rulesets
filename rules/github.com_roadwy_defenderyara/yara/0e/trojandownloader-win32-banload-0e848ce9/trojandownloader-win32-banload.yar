rule TrojanDownloader_Win32_Banload{
	meta:
		description = "TrojanDownloader:Win32/Banload,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {d7 88 c1 c1 e8 08 8b 5d ?? d7 30 c1 c1 e8 08 8b 5d ?? d7 30 c1 c1 e8 08 8b 5d ?? d7 } 		$a_03_1 = {55 89 e5 50 8b 45 ?? c6 00 ?? 40 c6 00 ?? 40 c6 00 ?? 40 c6 00 ?? 40 c6 00 ?? 40 c6 00 ?? 40 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}