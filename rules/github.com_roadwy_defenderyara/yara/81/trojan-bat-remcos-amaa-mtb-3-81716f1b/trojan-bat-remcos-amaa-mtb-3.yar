rule Trojan_BAT_Remcos_AMAA_MTB_3{
	meta:
		description = "Trojan:BAT/Remcos.AMAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 02 11 04 9a 28 ?? 00 00 0a 1f 62 da b4 6f ?? 00 00 0a 00 11 04 17 d6 13 04 11 04 09 31 e1 08 6f ?? 00 00 0a 0a 2b 00 06 2a } 		$a_01_1 = {47 00 65 00 74 00 4d 00 65 00 74 00 68 00 6f 00 64 00 73 00 00 0d 49 00 6e 00 76 00 6f 00 6b 00 65 00 00 09 4c 00 6f 00 61 00 64 } 	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}