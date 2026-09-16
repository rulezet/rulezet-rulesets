rule Trojan_BAT_Heracles_NHS_MTB{
	meta:
		description = "Trojan:BAT/Heracles.NHS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {6f 0e 00 00 0a 07 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 06 11 06 11 04 16 11 04 8e 69 6f ?? 00 00 0a } 		$a_01_1 = {52 00 61 00 6e 00 63 00 68 00 72 00 6f 00 73 00 65 00 32 00 32 00 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}