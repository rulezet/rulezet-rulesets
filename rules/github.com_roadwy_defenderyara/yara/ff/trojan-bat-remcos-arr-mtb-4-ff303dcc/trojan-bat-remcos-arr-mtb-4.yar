rule Trojan_BAT_Remcos_ARR_MTB_4{
	meta:
		description = "Trojan:BAT/Remcos.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 13 06 2b 30 00 11 06 11 04 5d 13 09 11 06 11 04 5b 13 0a 09 11 09 11 0a 6f ?? ?? ?? 0a 13 0b 08 12 0b 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 11 06 17 58 13 06 00 11 06 11 04 11 05 5a fe 04 13 0c 11 0c 2d c1 } 		$a_01_1 = {43 00 68 00 61 00 72 00 67 00 69 00 6e 00 67 00 50 00 69 00 6c 00 65 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}