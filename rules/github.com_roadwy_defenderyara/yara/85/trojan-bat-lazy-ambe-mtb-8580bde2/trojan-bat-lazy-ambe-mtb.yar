rule Trojan_BAT_Lazy_AMBE_MTB{
	meta:
		description = "Trojan:BAT/Lazy.AMBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {05 11 09 8f ?? 00 00 01 25 71 ?? 00 00 01 06 11 0e 91 61 d2 81 } 		$a_01_1 = {08 17 58 20 00 01 00 00 5d 0c 09 06 08 91 58 20 00 01 00 00 5d 0d 16 13 0a 06 08 91 13 0a } 		$a_80_2 = {6c 6c 64 2e 32 33 6c 65 6e 72 65 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_80_2  & 1)*1) >=5
 
}