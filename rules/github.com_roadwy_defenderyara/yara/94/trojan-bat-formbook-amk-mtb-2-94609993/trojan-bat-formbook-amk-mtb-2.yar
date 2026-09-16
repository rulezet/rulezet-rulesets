rule Trojan_BAT_FormBook_AMK_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.AMK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 05 1f 1f 5a 11 06 1f 11 5a 58 09 75 ?? ?? ?? 1b 8e 69 17 59 5f 13 08 1c 13 1a } 		$a_01_1 = {11 0b 17 59 25 13 0b 16 fe 02 16 fe 01 13 17 18 13 1a } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}