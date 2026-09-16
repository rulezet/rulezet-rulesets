rule Trojan_BAT_Redline_AR_MTB_2{
	meta:
		description = "Trojan:BAT/Redline.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 01 28 27 00 00 0a 13 06 38 09 00 00 00 11 03 13 04 38 13 00 00 00 11 06 28 02 00 00 2b 28 03 00 00 2b 13 03 } 		$a_01_1 = {76 00 69 00 72 00 74 00 6b 00 69 00 6f 00 73 00 6b 00 2e 00 65 00 78 00 65 00 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}