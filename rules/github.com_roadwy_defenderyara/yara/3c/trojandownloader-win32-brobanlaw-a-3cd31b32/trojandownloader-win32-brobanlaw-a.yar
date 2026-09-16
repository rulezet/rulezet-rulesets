rule TrojanDownloader_Win32_BrobanLaw_A{
	meta:
		description = "TrojanDownloader:Win32/BrobanLaw.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {c7 45 f4 01 00 00 00 8b 45 fc 8b 55 f4 33 db 8a 5c 10 ff 03 5d f8 8b c3 33 d2 52 50 8d 45 e8 e8 ?? ?? ?? ?? 8b 45 e8 e8 } 		$a_03_1 = {64 ff 35 00 00 00 00 64 89 25 00 00 00 00 58 c3 e9 90 09 05 00 68 } 		$a_03_2 = {2e 63 61 62 00 00 ff ff ff ff 0a 00 00 00 ?? ?? ?? ?? ?? ?? 2e 63 61 62 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}