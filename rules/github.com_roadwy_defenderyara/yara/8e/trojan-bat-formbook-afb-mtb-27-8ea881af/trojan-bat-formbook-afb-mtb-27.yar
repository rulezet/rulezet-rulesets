rule Trojan_BAT_FormBook_AFB_MTB_27{
	meta:
		description = "Trojan:BAT/FormBook.AFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {20 00 01 00 00 14 14 19 8d ?? ?? ?? 01 25 16 06 6f ?? ?? ?? 0a a2 25 17 16 8c ?? ?? ?? 01 a2 25 18 06 6f } 		$a_03_1 = {0a 16 0b 02 6f ?? 00 00 0a 17 59 0c 2b 18 00 06 07 93 0d 06 07 06 08 93 9d 06 08 09 9d 07 17 58 0b 08 17 59 0c 00 07 08 fe 04 13 04 11 04 2d de } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}