rule Trojan_BAT_LummaStealer_NL_MTB_5{
	meta:
		description = "Trojan:BAT/LummaStealer.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 28 9e 00 00 0a 39 ?? 00 00 00 7e ?? 00 00 04 74 2f 00 00 01 2a 07 17 58 0b 07 7e 3e 00 00 04 8e 69 3f d2 ff ff ff } 		$a_03_1 = {02 6f 9a 00 00 0a 6f ?? 00 00 0a 25 7e ?? 00 00 04 74 2f 00 00 01 6f 9a 00 00 0a 6f 9b 00 00 0a } 	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}