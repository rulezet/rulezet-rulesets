rule Trojan_BAT_Zilla_RR_MTB{
	meta:
		description = "Trojan:BAT/Zilla.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {61 19 11 1a 58 61 11 34 61 d2 9c 11 29 13 1a 17 11 0a 58 13 0a 11 0a 11 2a 32 a4 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}