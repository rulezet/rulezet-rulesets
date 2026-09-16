rule TrojanDownloader_Win32_Renos_IX{
	meta:
		description = "TrojanDownloader:Win32/Renos.IX,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 85 08 ff ff ff 0f b6 85 64 fc ff ff 0f b7 85 a4 fd ff ff 0f b7 85 54 fe ff ff 0f b6 85 90 fe ff ff e9 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}