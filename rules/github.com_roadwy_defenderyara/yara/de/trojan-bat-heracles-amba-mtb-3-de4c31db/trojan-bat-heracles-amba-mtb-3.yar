rule Trojan_BAT_Heracles_AMBA_MTB_3{
	meta:
		description = "Trojan:BAT/Heracles.AMBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 08 03 2d 18 07 06 28 ?? 00 00 0a 72 ?? ?? 00 70 6f ?? 00 00 0a 6f ?? 00 00 0a 2b 16 07 06 28 ?? 00 00 0a 72 ?? ?? 00 70 6f ?? 00 00 0a 6f ?? 00 00 0a 17 73 ?? 00 00 0a 0d 09 02 16 02 8e 69 6f ?? 00 00 0a 09 6f ?? 00 00 0a de 0a } 		$a_03_1 = {0a 0a 06 02 6f ?? 00 00 0a 06 03 6f ?? 00 00 0a 06 28 ?? 00 00 0a 6f ?? 00 00 0a 06 17 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}