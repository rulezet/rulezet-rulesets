rule Trojan_Win32_Downloader_RPG_MTB{
	meta:
		description = "Trojan:Win32/Downloader.RPG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {0f 3f 07 0b c7 45 84 00 00 00 00 c7 45 fc ff ff ff } 		$a_01_1 = {56 4d 77 61 72 65 } 	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}