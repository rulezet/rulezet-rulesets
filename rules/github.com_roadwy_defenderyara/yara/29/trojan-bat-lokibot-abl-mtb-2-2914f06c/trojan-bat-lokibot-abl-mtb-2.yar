rule Trojan_BAT_Lokibot_ABL_MTB_2{
	meta:
		description = "Trojan:BAT/Lokibot.ABL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0c 2b 1c 07 08 9a 03 28 ?? 00 00 06 0d 09 2c 05 16 2d e6 09 2a 08 1c 2c d9 17 25 2c 09 58 0c 15 2c e1 08 07 8e 69 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}