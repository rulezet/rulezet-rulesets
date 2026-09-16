rule Trojan_BAT_Hawkeye_AHW_MTB_5{
	meta:
		description = "Trojan:BAT/Hawkeye.AHW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {16 06 8e b7 17 da 0d 0c 2b 3f 06 08 91 1f 1f fe 02 06 08 91 1f 7f fe 04 5f 2c 14 06 08 13 04 11 04 06 11 04 91 08 1f 1f 5d 18 d6 b4 59 86 9c 06 08 91 1f 20 2f 0f 06 08 13 04 11 04 06 11 04 91 1f 5f 58 86 9c 08 17 d6 } 		$a_01_1 = {06 17 d6 20 00 01 00 00 5d 0a 08 11 08 06 91 d6 20 00 01 00 00 5d 0c 11 08 06 91 0b 11 08 06 11 08 08 91 9c 11 08 08 07 9c 11 08 06 91 11 08 08 91 d6 20 00 01 00 00 5d 13 05 02 50 11 0a 02 50 11 0a 91 11 08 11 05 91 61 9c 11 0a 17 d6 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}