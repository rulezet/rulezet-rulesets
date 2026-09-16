rule Trojan_BAT_Agensla_GG_MTB{
	meta:
		description = "Trojan:BAT/Agensla.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {02 09 02 8e 69 5d 02 09 02 8e 69 5d 91 07 09 07 8e 69 5d 91 61 02 09 17 d6 02 8e 69 5d 91 da [0-05] d6 [0-05] 5d b4 9c 09 15 d6 0d 09 16 2f cb } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}