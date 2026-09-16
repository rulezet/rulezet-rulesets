rule Trojan_BAT_Vidar_NVA_MTB{
	meta:
		description = "Trojan:BAT/Vidar.NVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {6f 76 00 00 0a 0b 07 02 16 02 8e 69 6f ?? 00 00 0a 0c 08 0d } 		$a_01_1 = {43 00 6f 00 37 00 66 00 65 00 72 00 65 00 37 00 63 00 65 00 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}