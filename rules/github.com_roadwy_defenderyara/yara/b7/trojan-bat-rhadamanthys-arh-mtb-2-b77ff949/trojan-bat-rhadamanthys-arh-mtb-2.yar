rule Trojan_BAT_Rhadamanthys_ARH_MTB_2{
	meta:
		description = "Trojan:BAT/Rhadamanthys.ARH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 05 11 06 6f ?? 00 00 0a 0d 00 07 16 fe 01 13 07 11 07 ?? ?? ?? ?? ?? ?? 16 0b 06 13 08 11 08 1f 20 2e 14 11 08 1f 2e 2e 77 } 		$a_03_1 = {08 09 1f 41 59 1f 5b 58 d2 28 ?? 00 00 06 00 00 2b 38 09 1f 61 32 07 09 1f 7a fe 02 2b 01 17 00 13 07 11 07 2d 18 00 7e ?? 00 00 04 08 09 1f 61 59 1f 75 58 d2 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}