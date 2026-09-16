rule Trojan_BAT_Disstl_AD_MTB{
	meta:
		description = "Trojan:BAT/Disstl.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 06 2c 63 00 03 8e 69 d1 0b 07 20 ff 00 00 00 fe 02 0d 09 2c 28 00 07 19 58 8d ?? ?? ?? 01 0c 08 16 16 9c 08 17 07 d2 9c 08 18 07 1e 63 d2 9c 03 16 08 19 07 28 ?? ?? ?? 0a 00 00 2b 1b 00 07 17 58 8d ?? ?? ?? 01 0c 08 16 07 d2 9c 03 16 08 17 07 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}