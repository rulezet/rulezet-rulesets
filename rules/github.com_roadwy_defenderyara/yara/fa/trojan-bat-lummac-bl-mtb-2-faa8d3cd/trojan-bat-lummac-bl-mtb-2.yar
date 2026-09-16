rule Trojan_BAT_LummaC_BL_MTB_2{
	meta:
		description = "Trojan:BAT/LummaC.BL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 07 28 ?? 00 00 0a 03 6f ?? 00 00 0a 6f ?? 00 00 0a 0c 06 08 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 06 6f ?? 00 00 0a 0d 02 28 ?? 00 00 0a 13 04 09 11 04 16 11 04 8e 69 6f ?? 00 00 0a 13 05 28 ?? 00 00 0a 11 05 6f ?? 00 00 0a 13 06 de } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}