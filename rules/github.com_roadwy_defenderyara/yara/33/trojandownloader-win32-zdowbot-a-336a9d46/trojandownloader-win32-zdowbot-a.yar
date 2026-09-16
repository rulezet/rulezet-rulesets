rule TrojanDownloader_Win32_Zdowbot_A{
	meta:
		description = "TrojanDownloader:Win32/Zdowbot.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 cd cc cc cc f7 e1 c1 ea 03 8d 04 92 03 c0 8b d1 2b d0 8a 82 ?? ?? ?? 00 30 04 39 41 3b ce 72 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}