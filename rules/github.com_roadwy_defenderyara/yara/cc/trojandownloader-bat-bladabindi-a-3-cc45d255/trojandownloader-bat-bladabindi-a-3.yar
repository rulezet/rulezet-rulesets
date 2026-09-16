rule TrojanDownloader_BAT_Bladabindi_A_3{
	meta:
		description = "TrojanDownloader:BAT/Bladabindi.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {45 00 6e 00 74 00 72 00 79 00 50 00 6f 00 69 00 6e 00 74 00 ?? ?? 49 00 6e 00 76 00 6f 00 6b 00 65 00 90 09 40 00 [0-08] (54 00 72 00 75 00 65 00|46 00 61 00 6c 00 73 00 65 00) ?? ?? 90 1e 01 00 00 90 1e 01 00 00 90 1e 01 00 00 90 1e 01 00 00 90 1e 01 00 00 90 1e 01 00 00 [0-04] ?? ?? 5c 00 ?? ?? 2e 00 65 00 78 00 65 00 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}