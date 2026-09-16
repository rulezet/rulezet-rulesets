rule Trojan_BAT_Bulz_NIT_MTB{
	meta:
		description = "Trojan:BAT/Bulz.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {02 6f 59 00 00 0a 0a 28 ?? 00 00 0a 03 6f ?? 00 00 0a 0b 06 73 93 00 00 0a 0c 08 07 6f ?? 00 00 0a 28 ?? 00 00 06 0d 2b 00 09 2a } 		$a_01_1 = {65 6e 63 72 79 70 74 69 6f 6e } 		$a_01_2 = {63 68 61 74 73 65 6e 64 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}