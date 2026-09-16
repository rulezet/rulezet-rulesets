rule TrojanDownloader_Win32_Agent_ZBC{
	meta:
		description = "TrojanDownloader:Win32/Agent.ZBC,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6a 65 73 75 73 65 72 2e 63 6e 2f 70 6c 75 67 2f 64 6f 53 65 6c 65 63 74 2e 61 73 70 3f 43 4d 44 3d 25 73 } 		$a_01_1 = {ff ff ff ff 0c 00 00 00 67 65 74 72 61 6e 64 74 69 6d 65 7c 00 00 00 00 ff ff ff ff 2c 00 00 00 68 74 74 70 3a 2f 2f 77 77 77 2e 71 71 68 75 64 6f 6e 67 2e 63 6e 2f 75 73 65 72 73 65 74 75 70 2e 61 73 70 3f 61 63 74 69 6f 6e 3d 00 00 00 00 ff ff ff ff 12 00 00 00 73 65 74 75 70 7c 25 73 } 		$a_01_2 = {5c 73 76 2f 2f 63 68 2f 2f 6f 73 74 2f 2f 2e 65 2f 2f 78 65 2f 2f 00 00 ff ff ff ff 06 00 00 00 63 6f 6d 6d 6f 6e 00 00 ff ff ff ff 04 00 00 00 65 78 65 63 00 00 00 00 ff ff ff ff 02 00 00 00 5c 5c 00 00 ff ff ff ff 08 00 00 00 77 5c 5c 64 6c 5c 5c 6c 00 00 00 00 ff ff ff ff 07 00 00 00 54 58 54 46 49 4c 45 00 ff ff ff ff 0c 00 00 00 45 78 70 6c 6f 72 65 72 2e 65 78 65 00 00 00 00 ff ff ff ff 05 00 00 00 6e 65 78 65 63 00 00 00 } 	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}