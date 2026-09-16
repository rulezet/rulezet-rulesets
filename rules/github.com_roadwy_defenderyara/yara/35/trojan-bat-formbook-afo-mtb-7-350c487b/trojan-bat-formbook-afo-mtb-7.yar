rule Trojan_BAT_FormBook_AFO_MTB_7{
	meta:
		description = "Trojan:BAT/FormBook.AFO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {19 5d 13 17 17 11 16 58 19 5d 13 18 18 11 16 58 19 5d 13 19 19 8d ?? 00 00 01 13 1a 11 1a 16 12 14 28 ?? 00 00 0a 9c 11 1a 17 12 14 28 ?? 00 00 0a 9c 11 1a 18 12 14 28 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}