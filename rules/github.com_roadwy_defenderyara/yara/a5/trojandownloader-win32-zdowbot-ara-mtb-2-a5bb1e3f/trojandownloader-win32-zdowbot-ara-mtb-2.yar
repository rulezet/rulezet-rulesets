rule TrojanDownloader_Win32_Zdowbot_ARA_MTB_2{
	meta:
		description = "TrojanDownloader:Win32/Zdowbot.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 fe ff 74 2f 6a 00 6a 00 ff d7 8b 0d 50 60 40 00 b8 67 66 66 66 f7 ee c1 fa 02 8b c2 c1 e8 1f 03 c2 8d 14 80 a1 00 60 40 00 03 d2 2b c2 8a 14 30 30 14 31 46 3b 35 5c 60 40 00 72 c3 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}