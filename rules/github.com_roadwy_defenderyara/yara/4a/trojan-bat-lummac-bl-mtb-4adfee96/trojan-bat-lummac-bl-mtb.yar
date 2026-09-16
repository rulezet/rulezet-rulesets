rule Trojan_BAT_LummaC_BL_MTB{
	meta:
		description = "Trojan:BAT/LummaC.BL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 2d 17 58 7e ?? 00 00 04 28 ?? 00 00 06 11 2f 7e ?? 00 00 04 28 ?? 00 00 06 7e ?? 00 00 04 28 ?? 00 00 06 7e ?? 00 00 04 28 ?? 00 00 06 5d } 		$a_03_1 = {02 11 31 8f ?? 00 00 01 25 47 11 35 16 6f ?? 00 00 0a 61 d2 52 38 } 	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}