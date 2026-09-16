rule Trojan_BAT_Remcos_AR_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0d 16 13 04 38 24 00 00 00 09 11 04 a3 02 00 00 01 13 05 08 11 05 6f } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}