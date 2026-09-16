rule Trojan_BAT_LummaStealer_NA_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {72 93 00 00 70 1b 28 ?? 00 00 06 72 93 00 00 70 28 ?? 00 00 0a 13 06 11 06 28 ?? 00 00 0a 16 } 		$a_01_1 = {6c 6f 61 64 5f 77 6f 72 6c 64 2e 65 78 65 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}