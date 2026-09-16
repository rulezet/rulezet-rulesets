rule Trojan_BAT_Remcos_ARC_MTB_5{
	meta:
		description = "Trojan:BAT/Remcos.ARC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 13 08 2b 11 04 11 06 11 08 91 6f ?? 00 00 0a 11 08 17 58 13 08 11 08 03 32 ea } 		$a_03_1 = {16 13 08 2b 34 09 11 08 8f ?? 00 00 01 25 47 11 04 11 08 58 1f 11 5a 20 00 01 00 00 5d d2 61 d2 52 11 04 1f 1f 5a 09 11 08 91 58 20 00 01 00 00 5d 13 04 11 08 17 58 13 08 11 08 09 8e 69 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}