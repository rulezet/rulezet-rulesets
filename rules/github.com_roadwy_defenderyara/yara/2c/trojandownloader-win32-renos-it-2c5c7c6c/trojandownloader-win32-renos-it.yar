rule TrojanDownloader_Win32_Renos_IT{
	meta:
		description = "TrojanDownloader:Win32/Renos.IT,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {88 04 3e 46 eb 90 09 05 00 35 ?? 00 00 00 } 		$a_01_1 = {68 ff ff 0d ba ff 15 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}