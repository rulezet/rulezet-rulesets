rule Trojan_BAT_DarkTortilla_RP_MTB_21{
	meta:
		description = "Trojan:BAT/DarkTortilla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,65 00 65 00 03 00 00 "
		
	strings :
		$a_03_0 = {25 16 02 a2 25 17 16 ?? ?? ?? ?? ?? a2 25 18 02 8e 69 ?? ?? ?? ?? ?? a2 25 13 08 14 14 19 } 		$a_03_1 = {0d 07 06 17 da 09 28 ?? ?? ?? ?? a2 07 06 28 ?? ?? ?? ?? 00 de 1f } 		$a_01_2 = {2e 67 2e 72 65 73 6f 75 72 63 65 73 } 	condition:
		((#a_03_0  & 1)*100+(#a_03_1  & 1)*100+(#a_01_2  & 1)*1) >=101
 
}