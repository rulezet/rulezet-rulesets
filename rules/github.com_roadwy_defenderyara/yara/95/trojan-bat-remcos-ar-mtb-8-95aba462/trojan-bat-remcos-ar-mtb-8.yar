rule Trojan_BAT_Remcos_AR_MTB_8{
	meta:
		description = "Trojan:BAT/Remcos.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 13 04 02 28 01 00 00 0a 13 05 28 09 00 00 0a 11 04 11 05 16 11 05 8e 69 6f 0f 00 00 0a 6f 10 00 00 0a 0c 08 13 06 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}