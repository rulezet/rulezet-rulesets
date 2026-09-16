rule Trojan_BAT_Lazy_ALZ_MTB_5{
	meta:
		description = "Trojan:BAT/Lazy.ALZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0d 2b 28 09 6f ?? 00 00 0a 74 ?? 00 00 01 13 04 00 11 04 72 ?? 00 00 70 6f ?? 00 00 0a 14 fe 01 13 05 11 05 2c 04 00 17 0a 00 00 09 6f } 		$a_03_1 = {11 07 17 6f ?? 00 00 0a 00 11 07 17 6f ?? 00 00 0a 00 11 07 16 6f ?? 00 00 0a 00 11 07 17 6f ?? 00 00 0a 00 73 19 00 00 0a 13 08 11 08 11 07 6f } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}