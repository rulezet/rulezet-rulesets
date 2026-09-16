rule Trojan_BAT_RevengeRat_ARR_MTB_4{
	meta:
		description = "Trojan:BAT/RevengeRat.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {13 06 09 28 ?? 00 00 0a 04 6f ?? 00 00 0a 6f ?? 00 00 0a 13 07 11 07 16 11 06 16 1f 10 28 ?? 00 00 0a 11 07 16 11 06 1f 0f 1f 10 28 ?? 00 00 0a 06 11 06 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 06 6f ?? 00 00 0a 13 05 03 13 04 11 05 11 04 16 11 04 8e b7 6f ?? 00 00 0a 0c 08 0b de 0f } 		$a_01_1 = {43 00 41 00 43 00 41 00 4f 00 2e 00 74 00 72 00 6f 00 6c 00 6f 00 6c 00 6f 00 } 		$a_01_2 = {42 00 45 00 54 00 49 00 53 00 45 00 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*3) >=6
 
}