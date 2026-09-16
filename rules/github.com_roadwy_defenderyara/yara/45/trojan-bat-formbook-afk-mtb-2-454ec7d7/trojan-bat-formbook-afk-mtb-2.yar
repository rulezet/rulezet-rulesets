rule Trojan_BAT_FormBook_AFK_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.AFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0a 2b 0d 00 06 28 ?? ?? ?? 06 00 00 06 17 58 0a 06 7e 08 00 00 04 8e 69 fe 04 0b 07 2d e5 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}