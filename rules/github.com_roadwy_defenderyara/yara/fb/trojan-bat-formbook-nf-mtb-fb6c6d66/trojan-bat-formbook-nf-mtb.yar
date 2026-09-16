rule Trojan_BAT_FormBook_NF_MTB{
	meta:
		description = "Trojan:BAT/FormBook.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {2f 40 08 11 06 58 16 32 39 08 11 06 58 02 } 		$a_03_1 = {1f 09 2e 32 03 07 59 28 ?? 00 00 0a 17 30 0b 04 08 } 	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}