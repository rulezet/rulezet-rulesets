rule TrojanDownloader_BAT_LummaStealer_RP_MTB_2{
	meta:
		description = "TrojanDownloader:BAT/LummaStealer.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {16 0a 38 04 00 00 00 06 17 58 0a 06 1b 32 f8 } 		$a_03_1 = {1b 0a 17 0b 17 0c 38 ?? ?? 00 00 07 08 5a 0b 08 17 58 0c 08 06 31 f4 } 	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*1) >=11
 
}