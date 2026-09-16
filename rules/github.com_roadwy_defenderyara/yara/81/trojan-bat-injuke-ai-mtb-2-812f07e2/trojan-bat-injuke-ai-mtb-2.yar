rule Trojan_BAT_Injuke_AI_MTB_2{
	meta:
		description = "Trojan:BAT/Injuke.AI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {80 24 00 00 04 00 de 0b 06 2c 07 06 6f 2c 00 00 0a 00 dc 16 0c 2b 1b 00 7e 24 00 00 04 08 7e 24 00 00 04 08 91 20 4b 03 00 00 59 d2 9c 00 08 17 58 0c 08 7e 24 00 00 04 8e 69 fe 04 0d 09 2d d7 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}