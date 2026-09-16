rule Trojan_BAT_FormBook_AOF_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.AOF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 34 2b 32 00 11 07 11 06 8e 69 5d 13 35 11 06 11 35 11 32 11 34 91 9c 03 11 32 11 34 91 6f ?? ?? ?? 0a 00 11 07 17 58 11 06 8e 69 5d 13 07 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}