rule TrojanDownloader_Win32_Zdowbot_A_2{
	meta:
		description = "TrojanDownloader:Win32/Zdowbot.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c6 44 24 13 76 c7 44 24 1c 40 00 00 00 c7 44 24 14 71 00 00 00 bf 7e 00 00 00 c7 44 24 20 15 00 00 00 } 		$a_01_1 = {8b d5 6b d2 76 b8 91 73 9f 5d f7 e2 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}