rule Trojan_BAT_LummaC_AMA_MTB{
	meta:
		description = "Trojan:BAT/LummaC.AMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6e 5b 26 11 ?? 6e 11 ?? 6a 5b 26 11 [0-32] 0a 26 03 11 ?? 8f ?? 00 00 01 25 71 ?? 00 00 01 06 11 ?? 91 61 d2 81 ?? 00 00 01 de 05 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}