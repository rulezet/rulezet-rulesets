rule Trojan_BAT_FormBook_AFM_MTB_13{
	meta:
		description = "Trojan:BAT/FormBook.AFM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {25 16 1f 3d 9d 6f ?? 00 00 0a 0c 08 16 9a 6f ?? 00 00 0a 13 06 11 06 72 ?? 09 00 70 28 ?? 00 00 0a 2d 02 2b 21 08 17 9a 6f } 		$a_01_1 = {6d 79 54 61 73 6b 53 63 68 65 64 75 6c 65 72 5c 6f 62 6a 5c 44 65 62 75 67 5c 6d 79 54 61 73 6b 53 63 68 65 64 75 6c 65 72 2e 70 64 62 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}