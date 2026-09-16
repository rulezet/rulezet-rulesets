rule TrojanDownloader_Win32_Neojit_A{
	meta:
		description = "TrojanDownloader:Win32/Neojit.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {68 00 23 00 00 e8 } 		$a_03_1 = {c7 40 4c 80 10 00 00 c7 40 50 7c 08 00 00 ba ?? ?? ?? ?? 89 50 54 eb ?? 00 00 00 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}