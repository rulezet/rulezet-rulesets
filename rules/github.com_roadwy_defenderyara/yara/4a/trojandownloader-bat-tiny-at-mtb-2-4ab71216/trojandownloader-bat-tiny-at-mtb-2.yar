rule TrojanDownloader_BAT_Tiny_AT_MTB_2{
	meta:
		description = "TrojanDownloader:BAT/Tiny.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 00 08 06 6f ?? 00 00 0a 6f ?? 00 00 0a 0d 07 09 28 ?? 00 00 0a 00 00 de 0b } 		$a_01_1 = {57 69 6e 64 6f 77 73 53 65 74 75 70 4d 61 6e 67 65 72 5c 6f 62 6a 5c 44 65 62 75 67 5c 57 69 6e 64 6f 77 73 53 65 74 75 70 4d 61 6e 67 65 72 2e 70 64 62 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}