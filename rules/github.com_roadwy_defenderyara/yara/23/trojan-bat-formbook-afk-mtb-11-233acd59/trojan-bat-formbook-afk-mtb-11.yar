rule Trojan_BAT_FormBook_AFK_MTB_11{
	meta:
		description = "Trojan:BAT/FormBook.AFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 8e 69 6a 5d d4 07 11 07 07 8e 69 6a 5d d4 91 08 11 07 08 8e 69 6a 5d d4 91 61 28 ?? 00 00 06 d2 07 11 07 17 6a 58 07 8e 69 6a 5d d4 91 28 ?? 00 00 06 d2 59 20 00 01 00 00 58 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}