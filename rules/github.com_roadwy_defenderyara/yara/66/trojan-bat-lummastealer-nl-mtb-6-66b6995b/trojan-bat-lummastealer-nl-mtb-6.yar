rule Trojan_BAT_LummaStealer_NL_MTB_6{
	meta:
		description = "Trojan:BAT/LummaStealer.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 13 16 11 16 20 ?? ?? ?? 80 2e 1d 11 16 20 ?? ?? ?? 7f 2e 14 08 11 05 07 91 11 06 07 91 58 58 0c 08 20 ?? ?? ?? 00 5d 0c 11 05 07 91 13 0f 11 05 07 11 05 08 91 9c 11 05 08 11 0f 9c 07 17 58 0b 07 20 00 01 00 00 32 b7 } 		$a_01_1 = {6b 6a 63 62 6b 6a 69 77 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}