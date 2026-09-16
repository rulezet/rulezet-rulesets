rule Trojan_BAT_Lazy_AMBE_MTB_2{
	meta:
		description = "Trojan:BAT/Lazy.AMBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 08 28 ?? 00 00 0a 72 ?? 00 00 70 6f ?? 00 00 0a 6f ?? 00 00 0a 08 28 ?? 00 00 0a 72 ?? 00 00 70 6f ?? 00 00 0a 6f ?? 00 00 0a 08 6f ?? 00 00 0a 07 16 07 8e 69 6f ?? 00 00 0a 0d de 0a } 		$a_80_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } 		$a_80_2 = {44 65 6c 61 79 } 	condition:
		((#a_03_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=4
 
}