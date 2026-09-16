rule Trojan_BAT_Remcos_SCCF_MTB{
	meta:
		description = "Trojan:BAT/Remcos.SCCF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {04 08 03 08 91 05 09 95 61 d2 9c 00 08 17 58 0c 08 03 8e 69 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}