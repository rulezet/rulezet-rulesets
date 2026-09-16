rule Trojan_BAT_Remcos_ARE_MTB_7{
	meta:
		description = "Trojan:BAT/Remcos.ARE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0d 16 13 04 2b 1f 08 11 04 07 11 04 91 09 11 04 09 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 9c 11 04 17 58 13 04 11 04 07 8e 69 32 da 06 08 6f ?? 00 00 0a 06 16 6f } 		$a_01_1 = {50 00 61 00 67 00 61 00 6d 00 65 00 6e 00 74 00 6f 00 2e 00 4e 00 6f 00 76 00 6f 00 62 00 61 00 6e 00 63 00 6f 00 2e 00 70 00 64 00 66 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}