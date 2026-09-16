rule Trojan_BAT_FormBook_AFF_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AFF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 06 2b 17 00 08 07 11 06 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 26 00 11 06 17 59 13 06 11 06 16 fe 04 16 fe 01 13 07 11 07 2d db } 		$a_01_1 = {51 00 75 00 61 00 6e 00 4c 00 79 00 42 00 61 00 6e 00 56 00 65 00 4d 00 61 00 79 00 42 00 61 00 79 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}