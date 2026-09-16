rule Trojan_BAT_Oskistealer_AOS_MTB_2{
	meta:
		description = "Trojan:BAT/Oskistealer.AOS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 06 11 04 9a 28 ?? 00 00 06 13 05 07 11 04 11 05 28 ?? 00 00 06 74 ?? 00 00 1b a2 09 07 11 04 9a 8e 69 58 } 		$a_03_1 = {0a 2c 26 07 8d ?? 00 00 01 0c 7e ?? 00 00 04 0d 2b 11 02 03 08 09 28 ?? 00 00 06 09 7e ?? 00 00 04 58 0d 09 07 32 eb } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}