rule TrojanDownloader_Win32_Cutwail_BE_2{
	meta:
		description = "TrojanDownloader:Win32/Cutwail.BE,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f0 05 01 01 01 01 51 8a c8 d3 c0 59 51 8a c8 eb 08 00 00 00 00 00 00 00 00 d3 c0 59 05 01 01 01 00 05 01 01 01 01 81 f9 35 7c 01 00 72 03 89 45 f0 } 		$a_01_1 = {78 76 72 66 69 65 72 2e 64 6c 6c 00 42 65 67 69 6e 53 65 61 72 63 68 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}