rule TrojanDownloader_Win32_Sinowal_A_2{
	meta:
		description = "TrojanDownloader:Win32/Sinowal.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {81 c9 92 07 00 00 83 f1 50 [0-10] c1 f9 0a } 		$a_03_1 = {8a 02 88 45 fb [0-10] 8a 55 fb 88 11 8b 45 ?? 83 c0 ?? 89 45 ?? eb } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}