rule TrojanDownloader_BAT_Small_ASM_MTB_2{
	meta:
		description = "TrojanDownloader:BAT/Small.ASM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 06 25 28 ?? 00 00 0a 17 8d ?? 00 00 01 25 16 72 ?? 00 00 70 a2 28 ?? 00 00 0a 02 7b ?? 00 00 0a 28 ?? 00 00 0a 7d ?? 00 00 0a 18 8d ?? 00 00 01 25 16 72 ?? 00 00 70 a2 25 17 16 8c ?? 00 00 01 a2 16 16 02 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}