rule TrojanDownloader_Win32_ValleyRat_CF{
	meta:
		description = "TrojanDownloader:Win32/ValleyRat.CF,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {69 00 6f 00 73 00 00 00 68 00 00 00 74 00 00 00 74 70 00 00 3a 2f 2f 00 77 00 00 00 7a 67 6c 00 2e 00 00 00 79 6a 67 00 6c 6a 00 00 73 68 00 00 67 00 00 00 6f 76 2e 00 63 6e 3a 00 31 00 00 00 33 00 00 00 35 38 30 00 2f 00 00 00 64 00 00 00 65 6d 00 00 6f 2f 76 00 32 00 00 00 70 6e 00 } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}