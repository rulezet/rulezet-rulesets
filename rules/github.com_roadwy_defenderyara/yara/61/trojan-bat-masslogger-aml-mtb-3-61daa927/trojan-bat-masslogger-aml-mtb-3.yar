rule Trojan_BAT_MassLogger_AML_MTB_3{
	meta:
		description = "Trojan:BAT/MassLogger.AML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 13 07 38 3b 01 00 00 00 02 11 05 11 07 6f ?? 00 00 0a 13 08 04 03 6f ?? 00 00 0a 59 13 09 07 72 fa 03 00 70 28 ?? 00 00 0a 2c 08 11 09 1f 64 fe 02 2b 01 16 13 0a 11 0a 2c 0d 00 11 09 1f 64 28 ?? 00 00 0a 13 09 00 11 09 19 fe 04 16 fe 01 13 0b 11 0b 2c 70 } 		$a_01_1 = {56 00 65 00 63 00 74 00 6f 00 72 00 5f 00 49 00 6e 00 74 00 65 00 72 00 6e 00 61 00 74 00 69 00 6f 00 6e 00 61 00 6c 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}