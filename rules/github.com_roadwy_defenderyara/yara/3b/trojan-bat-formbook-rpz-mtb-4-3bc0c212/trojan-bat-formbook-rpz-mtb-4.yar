rule Trojan_BAT_FormBook_RPZ_MTB_4{
	meta:
		description = "Trojan:BAT/FormBook.RPZ!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 28 15 00 00 0a 00 00 02 23 00 00 00 00 00 88 d3 40 73 16 00 00 0a 7d 01 00 00 04 02 7b 01 00 00 04 02 fe 06 04 00 00 06 73 17 00 00 0a 6f 18 00 00 0a 00 02 7b 01 00 00 04 17 6f 19 00 00 0a 00 02 7b 01 00 00 04 16 6f 1a 00 00 0a 00 2a } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}