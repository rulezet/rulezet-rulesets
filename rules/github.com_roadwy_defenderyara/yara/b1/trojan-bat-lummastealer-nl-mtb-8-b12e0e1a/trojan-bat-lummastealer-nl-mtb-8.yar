rule Trojan_BAT_LummaStealer_NL_MTB_8{
	meta:
		description = "Trojan:BAT/LummaStealer.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {1f 10 8d 76 00 00 01 13 14 11 09 28 ?? ?? ?? 0a 16 11 14 16 1a 28 ?? ?? ?? 0a 11 0a 28 36 } 		$a_01_1 = {70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 6d 00 5f 00 63 00 61 00 74 00 65 00 67 00 6f 00 72 00 69 00 65 00 73 00 5f 00 70 00 72 00 6f 00 64 00 75 00 63 00 74 00 73 00 5f 00 75 00 70 00 64 00 61 00 74 00 65 00 2e 00 65 00 78 00 65 00 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}