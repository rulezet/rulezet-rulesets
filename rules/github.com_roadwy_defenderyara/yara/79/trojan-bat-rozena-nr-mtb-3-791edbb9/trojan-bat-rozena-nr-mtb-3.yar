rule Trojan_BAT_Rozena_NR_MTB_3{
	meta:
		description = "Trojan:BAT/Rozena.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 13 00 00 0a 72 70 07 00 70 6f 14 00 00 0a 0b 28 ?? 00 00 0a 72 b2 07 00 70 6f 14 00 00 0a 0c 28 ?? 00 00 0a 07 08 28 ?? 00 00 06 0d 09 8e 69 13 04 } 		$a_01_1 = {45 76 61 73 69 6f 6e 53 75 69 74 65 2e 70 64 62 } 	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}