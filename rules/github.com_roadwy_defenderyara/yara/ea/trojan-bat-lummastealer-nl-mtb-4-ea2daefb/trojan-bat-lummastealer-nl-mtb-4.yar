rule Trojan_BAT_LummaStealer_NL_MTB_4{
	meta:
		description = "Trojan:BAT/LummaStealer.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 7e 65 03 00 04 28 ?? ?? 00 06 80 66 03 00 04 28 ?? ?? 00 06 28 a9 13 00 06 28 ?? ?? 00 06 61 28 ?? ?? 00 06 33 11 28 ?? ?? 00 06 80 66 03 00 04 } 		$a_01_1 = {4c 6f 61 64 65 72 56 31 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}