rule Trojan_Win32_DownloaderAgent_PA_MTB{
	meta:
		description = "Trojan:Win32/DownloaderAgent.PA!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 55 00 8d ac 24 1c 01 00 00 89 54 24 04 0f b6 14 02 88 14 24 8d 56 01 89 d7 c1 ff 1f c1 ef 18 8d 74 3e 01 81 e6 00 ff ff ff 29 f2 0f b6 7c 14 08 01 f9 89 ce c1 fe 1f c1 ee 18 01 ce 81 e6 00 ff ff ff 29 f1 0f b6 5c 0c 08 88 5c 14 08 89 fb 88 5c 0c 08 0f b6 5c 14 08 01 fb 0f b6 f3 8a 3c 24 32 7c 34 08 8b 74 24 04 88 3c 06 40 89 d6 3b 45 04 7c } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}