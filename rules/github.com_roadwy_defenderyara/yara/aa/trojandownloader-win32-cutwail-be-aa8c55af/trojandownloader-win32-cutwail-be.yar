rule TrojanDownloader_Win32_Cutwail_BE{
	meta:
		description = "TrojanDownloader:Win32/Cutwail.BE,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 f9 75 0f 95 c2 8b 45 0c 88 10 8b 4d 08 0f be 51 51 33 c0 83 fa 7a 0f 94 c0 } 		$a_01_1 = {8b 8d c0 fc ff ff 03 48 28 89 8d d8 fd ff ff } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}