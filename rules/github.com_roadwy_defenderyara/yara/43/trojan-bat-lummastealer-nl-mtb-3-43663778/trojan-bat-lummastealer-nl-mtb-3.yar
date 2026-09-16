rule Trojan_BAT_LummaStealer_NL_MTB_3{
	meta:
		description = "Trojan:BAT/LummaStealer.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {02 7b 05 00 00 04 26 16 0b de 34 08 02 7b 06 00 00 04 20 18 01 00 00 14 14 14 6f 1f 00 00 0a 26 17 0b } 		$a_01_1 = {28 1c 00 00 0a 02 7b 05 00 00 04 16 6f 1d 00 00 0a 0c 08 14 28 1e 00 00 0a } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}