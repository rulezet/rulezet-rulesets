rule Trojan_BAT_Hawkeye_AHW_MTB_2{
	meta:
		description = "Trojan:BAT/Hawkeye.AHW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b 4b 02 8e b7 17 58 8d ?? 00 00 01 0a 16 13 04 16 02 8e b7 17 59 13 06 13 05 2b 34 06 11 05 02 11 05 91 09 61 08 11 04 91 61 9c 08 28 ?? 00 00 0a 11 04 08 8e b7 17 59 33 05 16 13 04 2b 06 11 04 17 58 13 04 11 05 17 58 13 05 2b 03 0c 2b b2 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}