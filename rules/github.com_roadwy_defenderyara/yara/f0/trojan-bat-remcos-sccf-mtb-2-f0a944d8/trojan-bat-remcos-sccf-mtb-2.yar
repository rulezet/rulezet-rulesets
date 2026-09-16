rule Trojan_BAT_Remcos_SCCF_MTB_2{
	meta:
		description = "Trojan:BAT/Remcos.SCCF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 06 04 28 ?? 00 00 2b 05 28 ?? 00 00 2b 6f ?? 00 00 0a 0b 07 03 28 ?? 00 00 2b 16 03 28 ?? 00 00 2b 6f ?? 00 00 0a 0c de 14 07 2c 06 } 		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } 	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}