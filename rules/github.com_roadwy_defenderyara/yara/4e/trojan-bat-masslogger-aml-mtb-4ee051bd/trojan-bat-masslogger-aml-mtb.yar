rule Trojan_BAT_MassLogger_AML_MTB{
	meta:
		description = "Trojan:BAT/MassLogger.AML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 40 2b 23 00 03 11 3f 11 40 91 6f ?? ?? ?? 0a 00 11 14 1d 17 9c 11 0c 11 3f 11 40 91 58 13 0c 00 11 40 17 58 13 40 11 40 11 32 fe 04 13 41 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}