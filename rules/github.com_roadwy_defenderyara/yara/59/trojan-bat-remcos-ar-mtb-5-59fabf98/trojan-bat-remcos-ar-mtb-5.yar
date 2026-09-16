rule Trojan_BAT_Remcos_AR_MTB_5{
	meta:
		description = "Trojan:BAT/Remcos.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {1d 5f 58 13 04 2b 15 02 7b 69 00 00 04 18 1f 0a 28 ?? ?? ?? 06 11 04 1f 0a 59 13 04 11 04 16 30 e6 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}