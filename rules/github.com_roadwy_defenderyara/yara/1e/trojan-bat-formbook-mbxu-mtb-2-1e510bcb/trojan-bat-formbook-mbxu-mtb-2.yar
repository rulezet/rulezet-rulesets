rule Trojan_BAT_FormBook_MBXU_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.MBXU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 18 5d 2c ?? 02 06 07 6f ?? 00 00 0a 2b ?? 02 06 07 6f ?? 00 00 0a 0c 04 03 6f ?? 00 00 0a 59 0d 12 ?? 28 ?? 00 00 0a 13 ?? 12 } 		$a_01_1 = {4c 00 6f 00 61 00 64 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}