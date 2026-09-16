rule Trojan_BAT_Remcos_AMAA_MTB_4{
	meta:
		description = "Trojan:BAT/Remcos.AMAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 06 07 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 06 1b 6f ?? 00 00 0a 06 6f ?? 00 00 0a 0d 09 04 16 04 8e 69 6f ?? 00 00 0a 2a 73 2b 00 00 0a ?? 99 0a 2b 98 0b 2b 9e } 		$a_80_1 = {63 64 68 66 64 66 67 66 64 6b 66 66 73 68 64 68 64 73 68 64 67 68 66 } 		$a_80_2 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } 	condition:
		((#a_03_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}