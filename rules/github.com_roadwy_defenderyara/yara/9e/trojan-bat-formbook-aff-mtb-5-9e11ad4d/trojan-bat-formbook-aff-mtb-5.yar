rule Trojan_BAT_FormBook_AFF_MTB_5{
	meta:
		description = "Trojan:BAT/FormBook.AFF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 13 05 2b 2e 00 11 05 09 5d 13 08 11 05 09 5b 13 09 08 11 08 11 09 6f ?? ?? ?? 0a 13 0a 07 12 0a 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 11 05 17 58 13 05 00 11 05 09 11 04 5a fe 04 13 0b 11 0b 2d c4 } 		$a_01_1 = {51 00 4c 00 5f 00 4b 00 41 00 52 00 41 00 4f 00 4b 00 45 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}