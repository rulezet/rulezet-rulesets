rule Trojan_BAT_Remcos_ARS_MTB_2{
	meta:
		description = "Trojan:BAT/Remcos.ARS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 0b 06 8e 69 17 59 0c 38 16 00 00 00 06 07 91 0d 06 07 06 08 91 9c 06 08 09 9c 07 17 58 0b 08 17 59 0c 07 08 32 e6 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}