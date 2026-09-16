rule TrojanDownloader_Win32_Agent_ZDK{
	meta:
		description = "TrojanDownloader:Win32/Agent.ZDK,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0a 00 02 00 00 "
		
	strings :
		$a_00_0 = {77 77 77 2e 63 30 72 72 75 70 74 65 64 2e 63 6f 6d } 		$a_01_1 = {89 4c 24 04 b8 03 01 00 00 89 14 24 88 9d c8 fd ff ff bb 04 01 00 00 89 44 24 08 e8 d8 1a 00 00 89 5c 24 04 8d 9d c8 fd ff ff 89 1c 24 e8 26 1d 00 00 83 ec 08 89 5c 24 08 89 7c 24 04 bf 08 91 40 00 } 	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*10) >=10
 
}