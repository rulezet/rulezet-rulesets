rule TrojanDownloader_Win32_Agent_2{
	meta:
		description = "TrojanDownloader:Win32/Agent,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {33 c0 83 e1 03 f3 a4 bf 0c 52 40 00 83 c9 ff f2 ae f7 d1 2b f9 8b f7 8b d9 8b fa 83 c9 ff f2 ae } 		$a_00_1 = {68 74 74 70 3a 2f 2f 6b 65 65 70 70 75 72 65 2e 63 6e 2f 74 6f 6f 6c 2f 78 78 7a 2e 65 78 65 } 		$a_00_2 = {73 79 73 61 76 65 2e 65 78 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}