rule Trojan_BAT_FormBook_MBXT_MTB_3{
	meta:
		description = "Trojan:BAT/FormBook.MBXT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 11 05 11 06 6f ?? 00 00 0a 13 07 08 12 07 28 ?? 00 00 0a 6f ?? 00 00 0a 00 08 12 07 28 ?? 00 00 0a 6f ?? 00 00 0a 00 08 12 07 28 ?? 00 00 0a 6f ?? 00 00 0a 00 07 08 } 		$a_01_1 = {4c 00 6f 00 61 00 64 00 } 	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}