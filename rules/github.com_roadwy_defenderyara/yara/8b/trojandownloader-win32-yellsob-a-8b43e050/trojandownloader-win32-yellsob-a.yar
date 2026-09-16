rule TrojanDownloader_Win32_Yellsob_A{
	meta:
		description = "TrojanDownloader:Win32/Yellsob.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {76 2e 53 8b 5c 24 18 57 8a 44 14 10 8a 0c 1e 32 c8 8d 7c 24 10 88 0c 1e 83 c9 ff 33 c0 f2 ae f7 d1 8d 42 01 49 33 d2 f7 f1 46 3b f5 72 da } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}