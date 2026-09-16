rule TrojanDownloader_Win32_Banload_AMW{
	meta:
		description = "TrojanDownloader:Win32/Banload.AMW,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {51 37 48 71 53 33 65 6c 42 } 		$a_01_1 = {4a 4d 62 5a 53 63 7a 70 52 73 50 71 38 34 7a 63 50 63 62 5a 50 47 } 		$a_01_2 = {7c 65 8b 45 f0 c1 e0 06 03 d8 89 5d f0 83 c7 06 83 ff 08 7c 48 83 ef 08 8b cf 8b 5d f0 d3 eb 8b cf b8 01 00 00 00 d3 e0 50 8b 45 f0 5a 8b ca 99 f7 f9 89 55 f0 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}