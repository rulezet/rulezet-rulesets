rule TrojanDownloader_Win32_Ufraie_A{
	meta:
		description = "TrojanDownloader:Win32/Ufraie.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 07 00 00 "
		
	strings :
		$a_01_0 = {bb 0a 00 00 00 c7 45 f8 06 00 00 00 } 		$a_01_1 = {99 f7 f9 89 55 f0 83 fa 21 } 		$a_01_2 = {be 0a 00 00 00 bf 06 00 00 00 c7 45 fc 08 00 00 00 c7 45 f8 0a 00 00 00 } 		$a_01_3 = {c7 45 e8 09 00 00 00 c7 45 e4 03 00 00 00 bb 03 00 00 00 } 		$a_01_4 = {bb 03 00 00 00 c7 45 e0 0a 00 00 00 c7 45 dc 08 00 00 00 } 		$a_01_5 = {b9 14 00 00 00 99 f7 f9 } 		$a_01_6 = {bb 01 00 00 00 be 09 00 00 00 c7 45 cc 07 00 00 00 c7 45 c8 08 00 00 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=4
 
}