rule Trojan_BAT_FormBook_AFB_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.AFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 0a 11 0a 11 06 1f 16 5d 91 13 0b 11 04 11 06 91 11 0b 61 13 0c 11 06 18 58 17 59 11 05 5d } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}