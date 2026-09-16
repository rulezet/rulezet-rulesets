rule Trojan_BAT_FormBook_AFK_MTB_14{
	meta:
		description = "Trojan:BAT/FormBook.AFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 0a 2b 10 00 02 06 03 04 28 ?? 00 00 06 00 00 06 17 58 0a 06 02 6f ?? 00 00 0a 2f 0b 03 6f ?? 00 00 0a 04 fe 04 2b 01 16 0b 07 2d d7 } 		$a_01_1 = {42 00 75 00 61 00 4c 00 61 00 67 00 62 00 65 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}