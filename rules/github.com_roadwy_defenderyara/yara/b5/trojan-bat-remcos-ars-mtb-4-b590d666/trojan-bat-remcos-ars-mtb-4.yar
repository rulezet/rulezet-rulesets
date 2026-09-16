rule Trojan_BAT_Remcos_ARS_MTB_4{
	meta:
		description = "Trojan:BAT/Remcos.ARS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 13 22 2b 4a 00 11 22 11 04 5d 13 23 11 22 17 58 11 04 5d 13 24 07 11 24 91 20 00 01 00 00 58 13 25 07 11 23 91 13 26 11 26 08 11 22 1f 16 5d 91 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}