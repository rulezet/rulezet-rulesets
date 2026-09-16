rule Trojan_BAT_Remcos_ARE_MTB_4{
	meta:
		description = "Trojan:BAT/Remcos.ARE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {16 0b 2b 12 00 06 07 17 07 1f 1f 5f 62 1f 64 5a 9e 00 07 17 58 0b 07 06 8e 69 fe 04 0c 08 2d e4 } 		$a_03_1 = {16 0c 2b 18 00 06 19 28 ?? 00 00 06 0a 04 07 08 91 6f ?? 01 00 0a 00 00 08 17 58 0c 08 03 fe 04 0d 09 2d e0 } 	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}