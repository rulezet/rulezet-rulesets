rule Trojan_BAT_Nanocore_ANO_MTB_3{
	meta:
		description = "Trojan:BAT/Nanocore.ANO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {16 0a 2b 0e 02 03 06 04 05 28 ?? 00 00 06 06 17 58 0a 06 02 6f ?? 00 00 0a 2f 09 04 6f ?? 00 00 0a 05 32 e0 } 		$a_03_1 = {16 0a 2b 0d 02 06 03 04 28 ?? 00 00 06 06 17 58 0a 06 02 6f ?? 00 00 0a 2f 09 03 6f ?? 00 00 0a 04 32 e1 } 		$a_01_2 = {54 00 65 00 6d 00 70 00 65 00 72 00 61 00 74 00 75 00 72 00 65 00 43 00 6f 00 6e 00 76 00 65 00 72 00 74 00 65 00 72 00 } 	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=6
 
}