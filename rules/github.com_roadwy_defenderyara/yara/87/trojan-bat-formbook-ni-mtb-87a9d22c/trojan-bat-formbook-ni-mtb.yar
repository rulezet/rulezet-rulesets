rule Trojan_BAT_FormBook_NI_MTB{
	meta:
		description = "Trojan:BAT/FormBook.NI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 07 6f fd 00 00 0a 06 61 ?? ?? ?? ?? ?? 5a 0a 07 17 58 0b 07 02 6f e8 00 00 0a 2f 02 2b e1 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}