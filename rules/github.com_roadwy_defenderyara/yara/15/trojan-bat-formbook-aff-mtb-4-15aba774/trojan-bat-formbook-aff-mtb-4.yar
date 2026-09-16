rule Trojan_BAT_FormBook_AFF_MTB_4{
	meta:
		description = "Trojan:BAT/FormBook.AFF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 0d 2b 28 00 07 09 18 6f ?? ?? ?? 0a 20 03 02 00 00 28 ?? ?? ?? 0a 13 05 08 11 05 8c 5b 00 00 01 6f ?? ?? ?? 0a 26 09 18 58 0d 00 09 07 6f ?? ?? ?? 0a fe 04 13 06 11 06 2d c9 } 		$a_01_1 = {53 00 75 00 64 00 6f 00 6b 00 75 00 47 00 61 00 6d 00 65 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}