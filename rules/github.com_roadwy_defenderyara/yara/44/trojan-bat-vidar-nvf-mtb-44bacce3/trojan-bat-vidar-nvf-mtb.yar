rule Trojan_BAT_Vidar_NVF_MTB{
	meta:
		description = "Trojan:BAT/Vidar.NVF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 7b 16 00 00 04 17 6f ?? 00 00 0a 00 72 ?? 00 00 70 28 ?? 00 00 0a 26 2a } 		$a_01_1 = {39 61 6d 6f 75 73 2e 50 72 6f 70 65 72 74 69 65 73 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}