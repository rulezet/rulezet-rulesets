rule Trojan_BAT_FormBook_AFF_MTB_3{
	meta:
		description = "Trojan:BAT/FormBook.AFF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 04 2b 23 00 06 11 04 18 6f ?? ?? ?? 0a 13 05 07 11 04 18 5b 11 05 1f 10 28 ?? ?? ?? 0a d2 9c 00 11 04 18 58 13 04 11 04 06 6f ?? ?? ?? 0a fe 04 13 06 11 06 2d cd } 		$a_01_1 = {51 00 75 00 61 00 6e 00 4c 00 79 00 4e 00 68 00 61 00 6e 00 53 00 75 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}