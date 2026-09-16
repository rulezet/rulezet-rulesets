rule TrojanDownloader_AndroidOS_SAgnt_B_MTB_2{
	meta:
		description = "TrojanDownloader:AndroidOS/SAgnt.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 02 0b 00 38 02 ?? 00 22 04 ?? 00 70 10 ?? ?? 04 00 13 02 00 02 71 30 ?? ?? 0b 02 0c 02 5b 42 13 00 d0 00 00 02 d8 00 00 04 61 06 0f 00 71 20 ?? ?? 0b 00 0a 02 81 28 bd 86 5a 46 14 00 d8 00 00 04 61 06 0f 00 71 20 ?? ?? 0b 00 0a 02 81 28 bd 86 5a 46 15 00 d8 00 00 04 54 42 13 00 1a 05 ?? 00 6e 20 ?? ?? 52 00 0a 02 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}