rule Trojan_BAT_LummaStealer_NL_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {6f c5 07 00 0a 26 02 28 ?? 07 00 0a 0a } 		$a_03_1 = {28 c7 07 00 0a 06 16 06 8e 69 6f ?? 07 00 0a 2a } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}