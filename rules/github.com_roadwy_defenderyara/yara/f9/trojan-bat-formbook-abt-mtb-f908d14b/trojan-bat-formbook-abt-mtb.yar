rule Trojan_BAT_FormBook_ABT_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ABT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 09 5d 6f ?? 00 00 0a 13 0c 19 8d ?? 00 00 01 25 16 12 0c 28 ?? 00 00 0a 9c 25 17 12 0c 28 ?? 00 00 0a 9c 25 18 12 0c 28 ?? 00 00 0a 9c 13 0d 11 05 17 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}