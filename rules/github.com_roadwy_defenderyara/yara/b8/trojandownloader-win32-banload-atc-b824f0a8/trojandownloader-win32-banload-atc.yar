rule TrojanDownloader_Win32_Banload_ATC{
	meta:
		description = "TrojanDownloader:Win32/Banload.ATC,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff 10 00 00 00 90 04 10 10 41 42 43 44 45 46 30 31 32 33 34 35 36 37 38 39 00 00 00 00 ff ff ff ff 0e 00 00 00 90 04 0e 10 41 42 43 44 45 46 30 31 32 33 34 35 36 37 38 39 00 00 ff ff ff ff 10 00 00 00 90 04 10 10 41 42 43 44 45 46 30 31 32 33 34 35 36 37 38 39 00 00 00 00 ff ff ff ff 0e 00 00 00 90 04 0e 10 41 42 43 44 45 46 30 31 32 33 34 35 36 37 38 39 00 00 ff ff ff ff 10 00 00 00 90 04 10 10 41 42 43 44 45 46 30 31 32 33 34 35 36 37 38 39 00 00 00 00 ff ff ff ff 12 00 00 00 } 		$a_00_1 = {2e 63 70 6c 00 43 50 6c 41 70 70 6c 65 74 00 } 	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}