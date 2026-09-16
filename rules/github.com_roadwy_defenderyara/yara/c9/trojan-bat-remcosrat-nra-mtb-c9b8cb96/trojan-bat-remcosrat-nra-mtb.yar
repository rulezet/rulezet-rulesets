rule Trojan_BAT_RemcosRAT_NRA_MTB{
	meta:
		description = "Trojan:BAT/RemcosRAT.NRA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 04 73 02 00 00 0a 0c 2b 0b 28 ?? 00 00 0a 2b eb 13 04 2b eb 73 ?? 00 00 0a 0b 08 16 73 ?? 00 00 0a 73 ?? 00 00 0a 0d 09 07 6f ?? 00 00 0a de 07 } 		$a_01_1 = {4c 00 6f 00 78 00 61 00 64 00 } 		$a_01_2 = {41 00 7a 00 73 00 74 00 65 00 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}