rule Trojan_BAT_Vidar_NVF_MTB_2{
	meta:
		description = "Trojan:BAT/Vidar.NVF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {72 37 00 00 70 6f ?? ?? 00 0a 28 ?? ?? 00 0a 0a 2b 00 06 2a } 		$a_01_1 = {66 61 33 61 31 36 38 34 33 33 36 30 31 37 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}