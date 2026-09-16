rule Trojan_BAT_FormBook_MBCI_MTB{
	meta:
		description = "Trojan:BAT/FormBook.MBCI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 72 d5 05 00 70 72 d9 05 00 70 28 ?? 00 00 06 72 df 05 00 70 72 e3 05 00 70 6f ?? 00 00 0a 72 e9 05 00 70 72 ed 05 00 70 28 ?? 00 00 06 72 f3 05 00 70 72 f7 05 00 70 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}