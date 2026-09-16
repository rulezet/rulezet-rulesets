rule Trojan_BAT_Lazy_ALZ_MTB{
	meta:
		description = "Trojan:BAT/Lazy.ALZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 06 0b 72 ?? 01 00 70 0c 06 28 ?? 00 00 0a 16 fe 01 0d 09 2c 09 00 06 28 ?? 00 00 0a 26 00 73 ?? 00 00 0a 08 07 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}