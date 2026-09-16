rule TrojanDownloader_Win32_Zdowbot_ARA_MTB{
	meta:
		description = "TrojanDownloader:Win32/Zdowbot.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f8 99 b9 0a 00 00 00 f7 f9 a1 00 40 40 00 0f be 0c 10 8b 15 40 40 40 00 03 55 f8 0f be 02 33 c1 8b 0d 40 40 40 00 03 4d f8 88 01 eb b1 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}