rule Trojan_BAT_LummaC_ALM_MTB{
	meta:
		description = "Trojan:BAT/LummaC.ALM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {a1 56 4d e4 eb f7 61 9b 49 c4 d4 52 2a 2c 43 6e b6 5b be 1e fc f9 36 e8 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}