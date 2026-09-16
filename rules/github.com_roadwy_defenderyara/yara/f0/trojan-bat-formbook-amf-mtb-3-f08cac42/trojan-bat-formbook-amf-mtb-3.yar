rule Trojan_BAT_FormBook_AMF_MTB_3{
	meta:
		description = "Trojan:BAT/FormBook.AMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 07 11 0c 11 06 11 0c 9a 1f 10 28 ?? ?? ?? 0a 9c 11 0c 17 58 } 		$a_01_1 = {4d 00 61 00 69 00 6e 00 50 00 6c 00 61 00 79 00 65 00 72 00 4d 00 61 00 6e 00 61 00 67 00 65 00 6d 00 65 00 6e 00 74 00 46 00 6f 00 72 00 6d 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}