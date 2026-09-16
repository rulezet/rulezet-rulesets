rule Trojan_BAT_FormBook_AFM_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AFM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 0a 17 58 08 5d 13 0d 02 07 11 0a 91 11 0c 61 07 11 0d 91 59 28 ?? 00 00 06 13 0e 11 10 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}