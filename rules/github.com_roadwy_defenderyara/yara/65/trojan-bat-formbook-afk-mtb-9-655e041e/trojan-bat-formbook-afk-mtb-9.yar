rule Trojan_BAT_FormBook_AFK_MTB_9{
	meta:
		description = "Trojan:BAT/FormBook.AFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 11 12 0f 28 ?? 00 00 0a 13 12 12 0f 28 ?? 00 00 0a 13 13 12 0f 28 ?? 00 00 0a 13 14 11 0d 16 5f 13 15 11 15 19 5d 13 16 17 11 15 58 19 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}