rule Trojan_BAT_Dothetuk_ADH_MTB{
	meta:
		description = "Trojan:BAT/Dothetuk.ADH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 0e 2b 30 00 00 08 11 0c 11 0e 8f 14 00 00 02 7c 2c 00 00 04 7b 22 00 00 04 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 00 de 05 26 00 00 de 00 00 11 0e 17 58 13 0e 11 0e 6a 11 07 6e fe 04 13 0f 11 0f 2d c2 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}