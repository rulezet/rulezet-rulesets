rule TrojanDownloader_BAT_Bladabindi_A_2{
	meta:
		description = "TrojanDownloader:BAT/Bladabindi.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_03_0 = {de 00 1d 28 ?? ?? ?? ?? 72 ?? ?? ?? ?? 7e ?? ?? ?? ?? 72 ?? ?? ?? ?? 28 } 		$a_03_1 = {11 08 14 72 ?? ?? ?? ?? 16 8d 01 00 00 01 14 14 14 28 ?? ?? ?? ?? 14 72 ?? ?? ?? ?? 18 8d 01 00 00 01 } 		$a_00_2 = {00 6f 6b 2e 65 78 65 00 } 		$a_00_3 = {6c 69 6e 6b 73 20 53 74 61 72 74 55 50 20 68 61 73 68 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=1
 
}