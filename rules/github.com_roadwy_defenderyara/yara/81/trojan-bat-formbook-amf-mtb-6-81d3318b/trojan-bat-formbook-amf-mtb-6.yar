rule Trojan_BAT_FormBook_AMF_MTB_6{
	meta:
		description = "Trojan:BAT/FormBook.AMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {25 16 09 a2 25 17 19 8d ?? 00 00 01 25 16 02 7b ?? 00 00 04 a2 25 17 02 7b ?? 00 00 04 a2 25 18 } 		$a_01_1 = {16 0c 2b 1a 00 07 08 18 5b 02 08 18 6f 6f 00 00 0a 1f 10 28 70 00 00 0a 9c 00 08 18 58 0c 08 06 fe 04 0d 09 2d de } 		$a_01_2 = {53 00 65 00 61 00 72 00 63 00 68 00 5f 00 49 00 6e 00 64 00 65 00 78 00 65 00 72 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}