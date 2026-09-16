rule Trojan_BAT_LummaC_ALM_MTB_3{
	meta:
		description = "Trojan:BAT/LummaC.ALM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 02 16 09 16 09 8e 69 28 ?? 00 00 0a 06 09 6f ?? 00 00 0a 02 8e 69 09 8e 69 59 8d ?? 00 00 01 13 04 02 09 8e 69 11 04 16 11 04 8e 69 28 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}