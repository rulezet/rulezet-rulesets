rule TrojanDownloader_Win32_Tenega_B_MTB{
	meta:
		description = "TrojanDownloader:Win32/Tenega.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 0c 28 80 f1 80 88 0c 28 8b 4c 24 10 40 3b c1 72 ee } 		$a_01_1 = {8b 55 fc 8a 1c 11 80 c3 7a 88 1c 11 8b 55 fc 8a 1c 11 80 c3 fd 88 1c 11 8b 55 fc 80 04 11 03 90 8b 55 fc 8a 1c 11 80 f3 19 88 1c 11 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}