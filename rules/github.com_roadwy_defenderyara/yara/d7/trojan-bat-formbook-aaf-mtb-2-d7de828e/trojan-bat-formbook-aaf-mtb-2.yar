rule Trojan_BAT_FormBook_AAF_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.AAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 06 11 06 08 6f ?? ?? ?? 0a 00 08 6f ?? ?? ?? 0a 03 6a da 17 6a da 13 07 16 6a 13 08 2b 0f 07 1b 6f ?? ?? ?? 0a 00 11 08 17 6a d6 13 08 11 08 11 07 31 eb } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}