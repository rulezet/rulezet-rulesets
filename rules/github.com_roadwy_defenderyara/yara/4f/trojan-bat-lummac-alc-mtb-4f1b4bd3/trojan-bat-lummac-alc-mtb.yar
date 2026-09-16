rule Trojan_BAT_LummaC_ALC_MTB{
	meta:
		description = "Trojan:BAT/LummaC.ALC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 08 91 06 09 91 58 20 00 01 00 00 5d 13 06 02 11 05 8f 1e 00 00 01 25 47 06 11 06 91 61 d2 52 11 05 17 58 13 05 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}