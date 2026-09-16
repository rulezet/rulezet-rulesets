rule Trojan_BAT_Remcos_AR_MTB_7{
	meta:
		description = "Trojan:BAT/Remcos.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {17 2d 06 d0 38 00 00 06 26 72 5d 00 00 70 0a 06 28 73 00 00 0a 25 26 0b 28 74 00 00 0a 25 26 07 16 07 8e 69 6f } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}