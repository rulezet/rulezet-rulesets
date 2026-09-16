rule Trojan_BAT_FormBook_NC_MTB{
	meta:
		description = "Trojan:BAT/FormBook.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 09 07 8e 69 5d 91 08 09 08 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 07 09 17 58 07 8e 69 5d 91 59 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}