rule Trojan_BAT_MassLogger_MBXT_MTB{
	meta:
		description = "Trojan:BAT/MassLogger.MBXT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 06 07 6f ?? 00 00 0a 0c 03 6f ?? 00 00 0a 19 58 04 fe ?? 16 fe ?? 0d 09 2c } 		$a_01_1 = {43 00 72 00 65 00 61 00 74 00 65 00 49 00 6e 00 73 00 74 00 61 00 6e 00 63 00 65 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}