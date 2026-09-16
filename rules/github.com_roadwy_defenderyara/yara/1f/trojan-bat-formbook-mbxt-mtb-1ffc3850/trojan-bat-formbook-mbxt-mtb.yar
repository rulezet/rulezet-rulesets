rule Trojan_BAT_FormBook_MBXT_MTB{
	meta:
		description = "Trojan:BAT/FormBook.MBXT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 91 04 06 28 ?? 00 00 0a 05 6f ?? 00 00 0a 8e 69 5d 91 61 d2 9c 00 06 17 58 0a } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}