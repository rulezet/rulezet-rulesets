rule Trojan_BAT_Vidar_AVD_MTB{
	meta:
		description = "Trojan:BAT/Vidar.AVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 34 12 1f 28 ?? 00 00 0a 12 34 28 ?? 00 00 0a 26 16 13 35 12 28 28 ?? 00 00 0a 28 ?? 00 00 0a 13 35 03 11 34 91 13 36 06 11 35 91 13 37 11 36 11 37 61 d2 13 36 03 11 34 11 36 9c } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}