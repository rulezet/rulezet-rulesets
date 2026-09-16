rule TrojanDownloader_Win32_Drixed_B_2{
	meta:
		description = "TrojanDownloader:Win32/Drixed.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {2e 73 64 61 74 61 00 00 20 00 00 00 3f 00 00 00 2e 4b 42 00 44 69 73 70 6c 61 79 4e 61 6d 65 90 09 04 00 5f 00 00 00 } 		$a_03_1 = {81 3b ef be ad de 74 ?? eb } 		$a_01_2 = {c7 40 08 f7 28 9e 50 ff 15 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}