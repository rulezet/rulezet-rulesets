rule Trojan_BAT_Hawkeye_AHW_MTB_4{
	meta:
		description = "Trojan:BAT/Hawkeye.AHW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8e b7 17 59 13 06 13 05 2b 2b 11 04 11 05 02 11 05 91 06 61 08 07 91 61 9c 08 28 ?? 00 00 0a 07 08 8e b7 17 59 33 04 16 0b 2b 04 07 17 58 0b 11 05 17 58 } 		$a_03_1 = {0d 0c 2b 46 07 08 91 1f 1f 31 24 07 08 91 1f 7f 2f 1d 07 13 04 11 04 08 13 05 11 05 11 04 11 05 91 08 1f 1f 5d 16 58 28 ?? 00 00 0a 59 d2 9c 07 08 91 1f 20 32 02 2b 0e 07 08 07 08 91 1f 5f 58 28 ?? 00 00 0a 9c 08 17 58 0c } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}