rule TrojanDownloader_Win32_Annia_A{
	meta:
		description = "TrojanDownloader:Win32/Annia.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {be 82 23 00 00 68 ?? ?? 40 00 ff 15 90 20 59 22 da 2d 4e 75 f2 } 		$a_01_1 = {75 67 67 63 3a 2f 2f 34 36 2e 31 34 38 2e 31 39 2e 37 34 2f 6e 69 2e 72 6b 72 } 		$a_03_2 = {53 53 6a 03 53 6a 03 53 68 ?? ?? 40 00 c7 45 64 ?? ?? 40 00 c7 45 68 ?? ?? 40 00 c7 45 6c ?? ?? 40 00 89 5d 70 ff 15 90 20 bb a0 ae 1d } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}