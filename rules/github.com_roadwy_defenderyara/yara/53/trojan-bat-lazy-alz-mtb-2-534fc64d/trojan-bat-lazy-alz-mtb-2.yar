rule Trojan_BAT_Lazy_ALZ_MTB_2{
	meta:
		description = "Trojan:BAT/Lazy.ALZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 fe 01 0b 07 2c 09 00 06 28 ?? ?? ?? 0a 26 00 02 18 18 73 11 00 00 0a 0c 00 08 03 16 03 8e 69 6f ?? ?? ?? 0a 00 00 de 0b 08 2c 07 08 6f } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}