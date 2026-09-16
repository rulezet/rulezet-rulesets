rule Trojan_BAT_MassLogger_AML_MTB_2{
	meta:
		description = "Trojan:BAT/MassLogger.AML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 0b 2b 2d 02 06 07 28 ?? 00 00 06 0c 04 03 6f ?? 00 00 0a 59 0d 03 08 09 28 ?? 00 00 06 03 08 09 28 ?? 00 00 06 03 04 28 ?? 00 00 06 07 17 58 0b 07 02 6f } 		$a_01_1 = {54 00 69 00 63 00 54 00 61 00 63 00 54 00 6f 00 65 00 57 00 69 00 6e 00 46 00 6f 00 72 00 6d 00 73 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}