rule Trojan_BAT_Lazy_ALZ_MTB_4{
	meta:
		description = "Trojan:BAT/Lazy.ALZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0c 06 07 28 ?? 00 00 0a 28 ?? 00 00 0a 2d 0d 06 07 28 ?? 00 00 0a 08 28 ?? 00 00 0a de 14 26 72 ?? 01 00 70 02 28 } 		$a_01_1 = {0a 0c 08 28 06 00 00 0a 02 6f 07 00 00 0a 6f 08 00 00 0a 08 06 6f 09 00 00 0a 08 08 6f 0a 00 00 0a 08 6f 0b 00 00 0a 6f 0c 00 00 0a 0d 07 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}