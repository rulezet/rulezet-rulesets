rule Trojan_BAT_Vidar_NV_MTB_3{
	meta:
		description = "Trojan:BAT/Vidar.NV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {73 0c 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 0a 17 8d ?? 00 00 01 0d 09 16 17 8d ?? 00 00 01 25 13 04 11 04 16 7f ?? 00 00 04 d3 16 58 47 69 20 ?? 00 00 00 61 9d 73 ?? 00 00 0a a2 09 16 6f ?? 00 00 0a } 		$a_01_1 = {75 72 63 68 69 6e 73 53 61 70 66 75 6c } 		$a_01_2 = {73 61 70 66 75 6c 57 69 73 70 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}