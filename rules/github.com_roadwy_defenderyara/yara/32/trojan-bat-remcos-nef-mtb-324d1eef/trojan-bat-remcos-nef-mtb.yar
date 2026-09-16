rule Trojan_BAT_Remcos_NEF_MTB{
	meta:
		description = "Trojan:BAT/Remcos.NEF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_01_0 = {73 06 00 00 06 25 6f 07 00 00 06 25 6f 08 00 00 06 25 6f 09 00 00 06 2b 01 2a 6f 0a 00 00 06 2b f8 } 		$a_01_1 = {2b c9 02 2b cd 28 01 00 00 06 2b cd 28 1b 00 00 0a 2b c8 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*4) >=9
 
}