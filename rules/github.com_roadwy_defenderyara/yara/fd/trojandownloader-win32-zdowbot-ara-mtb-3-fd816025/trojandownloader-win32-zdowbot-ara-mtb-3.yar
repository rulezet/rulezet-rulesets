rule TrojanDownloader_Win32_Zdowbot_ARA_MTB_3{
	meta:
		description = "TrojanDownloader:Win32/Zdowbot.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 fe ff 74 33 6a 00 6a 00 6a 00 6a 00 ff d7 8b 0d 2c 40 40 00 b8 67 66 66 66 f7 ee c1 fa 02 8b c2 c1 e8 1f 03 c2 8d 14 80 a1 00 40 40 00 03 d2 2b c2 8a 14 30 30 14 31 46 3b 35 38 40 40 00 72 bf 5f 5e 5b c3 cc cc cc 53 56 57 eb 73 e8 22 0d } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}