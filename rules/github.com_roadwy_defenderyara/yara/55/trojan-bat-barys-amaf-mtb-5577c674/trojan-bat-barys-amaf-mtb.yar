rule Trojan_BAT_Barys_AMAF_MTB{
	meta:
		description = "Trojan:BAT/Barys.AMAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 1b 11 09 11 21 11 23 61 11 1a 19 58 61 11 2e 61 d2 9c } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}