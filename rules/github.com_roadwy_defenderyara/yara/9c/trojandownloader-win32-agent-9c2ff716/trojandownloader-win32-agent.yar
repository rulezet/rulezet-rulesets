rule TrojanDownloader_Win32_Agent{
	meta:
		description = "TrojanDownloader:Win32/Agent,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {63 3a 5c 6a 64 69 6f 6a 2e 74 78 74 } 		$a_02_1 = {ff ff ff ff 08 00 00 00 90 04 04 0a 30 31 32 33 34 35 36 37 38 39 2e 63 6f 6d } 		$a_02_2 = {ff ff ff ff 07 00 00 00 90 04 04 0a 30 31 32 33 34 35 36 37 38 39 2e 63 6e } 	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}