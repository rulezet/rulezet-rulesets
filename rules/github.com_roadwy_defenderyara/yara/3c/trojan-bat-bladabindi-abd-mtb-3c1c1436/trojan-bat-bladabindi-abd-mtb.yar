rule Trojan_BAT_Bladabindi_ABD_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.ABD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {20 00 0c 00 00 28 ?? ?? ?? 0a 06 03 6f ?? ?? ?? 0a 0b 07 8e 69 16 31 04 07 0c de 0e 14 0c de 0a 06 2c 06 06 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}