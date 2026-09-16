rule Trojan_BAT_Scarsi_AS_MTB{
	meta:
		description = "Trojan:BAT/Scarsi.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 04 16 0a 2b 17 11 04 09 06 09 8e 69 5d 91 08 06 91 61 d2 6f ?? ?? ?? 0a 06 17 58 0a 06 08 8e 69 32 e3 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}