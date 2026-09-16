rule Trojan_BAT_LummaStealer_NL_MTB_2{
	meta:
		description = "Trojan:BAT/LummaStealer.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {8d 06 00 00 01 14 14 14 28 44 00 00 0a 28 52 00 00 0a 02 } 		$a_03_1 = {7b 66 00 00 04 14 72 ?? 01 00 70 16 8d ?? 00 00 01 14 14 14 28 ?? 00 00 0a 28 37 00 00 0a } 	condition:
		((#a_01_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}