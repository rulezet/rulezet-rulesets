rule Trojan_BAT_NJRat_ARA_MTB{
	meta:
		description = "Trojan:BAT/NJRat.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 02 09 11 04 9a 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 13 05 06 09 11 04 17 58 9a 28 ?? ?? ?? 0a 11 05 28 ?? ?? ?? 0a 00 06 09 11 04 17 58 9a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 26 00 11 04 18 58 13 04 11 04 09 28 ?? ?? ?? 2b 17 59 fe 04 13 07 11 07 2d af } 		$a_01_1 = {5c 6f 62 6a 5c 44 65 62 75 67 5c 53 74 75 62 42 69 6e 64 65 72 2e 70 64 62 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}