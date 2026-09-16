rule TrojanDownloader_Win32_Banload_ADG_2{
	meta:
		description = "TrojanDownloader:Win32/Banload.ADG,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {c2 08 00 53 a1 ?? ?? ?? ?? 83 38 00 74 ?? 8b 1d ?? ?? ?? ?? 8b 1b ff d3 5b c3 ?? 55 8b ec 51 53 56 57 89 4d fc 8b da 8b f0 8b c3 ff 50 f4 } 		$a_02_1 = {43 3a 5c 73 79 73 36 34 5c [0-08] 2e 65 78 65 } 		$a_02_2 = {2f 6a 75 62 61 73 2f [0-08] 2e 65 78 65 } 		$a_00_3 = {59 4d 44 20 72 65 63 61 6c 63 20 6f 72 64 65 72 3a } 		$a_00_4 = {44 4d 59 20 72 65 63 61 6c 63 20 6f 72 64 65 72 3a } 	condition:
		((#a_03_0  & 1)*2+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}