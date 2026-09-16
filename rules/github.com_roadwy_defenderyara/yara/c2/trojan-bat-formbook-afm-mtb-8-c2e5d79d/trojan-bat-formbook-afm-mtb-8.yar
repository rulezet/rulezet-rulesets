rule Trojan_BAT_FormBook_AFM_MTB_8{
	meta:
		description = "Trojan:BAT/FormBook.AFM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 05 17 8d 08 00 00 01 25 16 7e 4b 00 00 04 a2 13 06 72 f2 16 00 70 72 bf 18 00 70 72 01 00 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 13 07 11 07 09 11 05 14 14 11 06 } 		$a_01_1 = {41 00 76 00 74 00 6f 00 70 00 61 00 72 00 6b 00 2e 00 65 00 78 00 65 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}