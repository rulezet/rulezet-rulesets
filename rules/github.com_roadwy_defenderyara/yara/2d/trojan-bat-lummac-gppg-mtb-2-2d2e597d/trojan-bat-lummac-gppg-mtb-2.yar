rule Trojan_BAT_LummaC_GPPG_MTB_2{
	meta:
		description = "Trojan:BAT/LummaC.GPPG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 0e 6e 11 29 6a 31 0d 11 26 11 13 61 13 0e 11 0d 11 1c 5b 26 16 13 2f 16 13 30 2b 34 } 	condition:
		((#a_01_0  & 1)*4) >=4
 
}