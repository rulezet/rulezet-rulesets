rule Trojan_BAT_Disstl_ADS_MTB{
	meta:
		description = "Trojan:BAT/Disstl.ADS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {72 01 00 00 70 0a 73 14 00 00 0a 0b 07 6f ?? ?? ?? 0a 72 f6 00 00 70 72 10 01 00 70 6f ?? ?? ?? 0a 00 72 32 01 00 70 02 72 4e 01 00 70 28 ?? ?? ?? 0a 0c 07 06 28 } 		$a_01_1 = {54 00 65 00 6d 00 70 00 5c 00 4d 00 61 00 68 00 65 00 73 00 68 00 2e 00 74 00 78 00 74 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}