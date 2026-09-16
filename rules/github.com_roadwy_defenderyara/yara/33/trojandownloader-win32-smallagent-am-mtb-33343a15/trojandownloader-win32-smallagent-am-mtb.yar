rule TrojanDownloader_Win32_SmallAgent_AM_MTB{
	meta:
		description = "TrojanDownloader:Win32/SmallAgent.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 46 04 80 f7 f7 8b 0e c0 e3 03 0a 5d 0c 80 cb c0 88 3c 01 8b 46 04 8b 0e 5f 88 5c 01 01 83 46 04 02 c7 46 08 } 		$a_01_1 = {08 48 01 8b 4b 04 8b 03 80 4c 01 01 04 8b 4b 04 8b 03 80 4c 01 01 80 8b 4b 04 8b 03 80 4c 01 02 24 8b 4b 04 8b 03 41 89 4b 04 c7 44 01 02 00 00 00 00 8b cb 83 43 04 06 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}