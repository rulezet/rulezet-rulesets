rule TrojanDownloader_BAT_LummaStealer_RP_MTB{
	meta:
		description = "TrojanDownloader:BAT/LummaStealer.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 08 02 08 91 07 08 07 6f ?? ?? 00 0a 5d 6f ?? ?? 00 0a 61 d2 9c 08 17 58 0c 08 02 8e 69 32 e0 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}