rule Trojan_BAT_FormBook_AFM_MTB_4{
	meta:
		description = "Trojan:BAT/FormBook.AFM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 05 2b 21 00 02 7b ?? 00 00 04 11 05 02 7b ?? 00 00 04 11 05 91 20 e5 05 00 00 59 d2 9c 00 11 05 17 58 13 05 11 05 02 7b ?? 00 00 04 8e 69 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}