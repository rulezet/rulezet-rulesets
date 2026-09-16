rule TrojanDownloader_Win32_Begseabug_A_2{
	meta:
		description = "TrojanDownloader:Win32/Begseabug.A,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 81 ec 74 08 00 00 8b 45 c4 53 33 db 56 3b c3 57 be 1f ab 01 01 74 ?? be 1f ab 01 01 b9 81 00 00 00 } 		$a_00_1 = {8a 04 1a 88 45 ff 8a 45 ff c0 c0 03 88 45 ff 8a 45 ff 32 44 0d c8 41 83 f9 10 88 04 1a } 	condition:
		((#a_03_0  & 1)*5+(#a_00_1  & 1)*5) >=10
 
}