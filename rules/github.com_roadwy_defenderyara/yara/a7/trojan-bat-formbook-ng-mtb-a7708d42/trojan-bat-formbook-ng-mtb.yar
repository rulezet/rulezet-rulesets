rule Trojan_BAT_FormBook_NG_MTB{
	meta:
		description = "Trojan:BAT/FormBook.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {5d 91 61 07 11 ?? 17 58 07 8e 69 5d 91 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}