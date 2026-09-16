rule Trojan_BAT_LummaC_ALC_MTB_2{
	meta:
		description = "Trojan:BAT/LummaC.ALC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {17 58 11 31 5d 13 2f 11 30 11 2d 11 2f 91 58 11 31 5d 13 30 73 1a 00 00 0a 13 66 11 66 11 2d 11 30 91 6f ?? 00 00 0a 11 2d 11 30 11 2d 11 2f 91 9c 11 2d 11 2f 11 66 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}