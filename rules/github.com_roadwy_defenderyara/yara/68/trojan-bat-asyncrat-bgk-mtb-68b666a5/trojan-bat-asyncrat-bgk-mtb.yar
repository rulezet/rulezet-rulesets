rule Trojan_BAT_AsyncRAT_BGK_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.BGK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 07 14 fe 01 13 06 11 06 2c 02 2b 35 07 ?? ?? 00 00 0a 0c 08 ?? ?? 00 00 0a 0d 09 ?? ?? 00 00 0a 8e 2d 03 14 2b 0f 17 8d 10 00 00 01 25 16 16 8d 24 00 00 01 a2 13 04 09 14 11 04 ?? ?? 00 00 0a 26 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}