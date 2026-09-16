rule TrojanDownloader_Win32_Zlob_AON{
	meta:
		description = "TrojanDownloader:Win32/Zlob.AON,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_01_0 = {6d 69 63 68 6c 65 6e 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 } 		$a_00_1 = {44 33 35 38 2d 34 38 41 33 2d 41 35 43 37 } 		$a_01_2 = {62 65 65 67 72 6f 63 6b 73 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 } 		$a_01_3 = {74 15 8b 77 40 03 f0 eb 09 8b 1e 03 d8 01 03 83 c6 04 83 3e 00 75 f2 8b 74 24 24 8b de 03 f0 b9 01 00 00 00 33 c0 f0 0f b1 4f 30 75 f7 ac } 	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*10) >=11
 
}