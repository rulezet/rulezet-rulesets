rule Trojan_BAT_Remcos_AR_MTB_13{
	meta:
		description = "Trojan:BAT/Remcos.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 16 13 04 2b 1e 09 06 11 04 06 8e 69 5d 91 08 11 04 91 61 d2 6f ?? ?? ?? 0a 11 04 13 05 11 05 17 58 13 04 11 04 08 8e 69 32 db } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}