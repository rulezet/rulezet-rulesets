rule TrojanDownloader_Win32_Vundo_HIZ{
	meta:
		description = "TrojanDownloader:Win32/Vundo.HIZ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 40 10 8b 04 85 e8 3e 41 00 8a 00 88 45 c0 a1 d0 3e 41 00 03 05 4c 36 41 00 8a 00 32 45 c0 8b 0d d0 3e 41 00 03 0d 4c 36 41 00 88 01 e9 99 fe ff ff } 		$a_01_1 = {e8 37 35 00 00 e8 fb 5c ff ff } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}