rule Trojan_BAT_Heracles_MBKS_MTB{
	meta:
		description = "Trojan:BAT/Heracles.MBKS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {54 00 65 00 73 00 74 00 31 00 32 00 2e 00 43 00 6c 00 61 00 73 00 73 00 31 00 00 13 46 00 69 00 6b 00 72 00 61 00 68 00 61 00 63 00 6b } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}