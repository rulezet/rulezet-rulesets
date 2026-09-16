rule Trojan_BAT_Jalapeno_NIT_MTB_3{
	meta:
		description = "Trojan:BAT/Jalapeno.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 08 17 28 ?? 00 00 0a 28 ?? 00 00 0a 03 08 03 6f 07 00 00 0a 5d 17 d6 17 28 ?? 00 00 0a 28 ?? 00 00 0a da 13 04 06 11 04 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0a 08 17 d6 0c 00 08 09 fe 02 16 fe 01 13 05 11 05 2d b5 } 		$a_03_1 = {a2 00 11 0a 28 ?? 00 00 0a 07 28 ?? 00 00 06 28 ?? 00 00 0a 13 09 11 09 28 ?? 00 00 0a 0a 06 28 ?? 00 00 0a 13 08 11 08 6f ?? 00 00 0a 14 14 6f ?? 00 00 0a 26 } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}