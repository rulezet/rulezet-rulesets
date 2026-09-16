rule Trojan_BAT_FormBook_AFM_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.AFM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 8e 69 5d 91 13 06 08 11 05 1f 16 5d 91 13 07 07 11 05 07 11 05 91 11 07 61 11 06 59 20 00 01 00 00 58 20 ff 00 00 00 5f d2 9c 00 11 05 17 58 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}