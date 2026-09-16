rule Trojan_BAT_Rozena_NR_MTB{
	meta:
		description = "Trojan:BAT/Rozena.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 01 00 00 06 0b 16 07 06 28 ?? 00 00 0a 7e ?? 00 00 0a 16 07 7e ?? 00 00 0a 16 7e ?? 00 00 0a 28 ?? 00 00 06 15 } 		$a_01_1 = {4f 66 66 65 6e 73 69 76 65 53 68 61 72 70 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}