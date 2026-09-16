rule Trojan_BAT_Redline_ARD_MTB_2{
	meta:
		description = "Trojan:BAT/Redline.ARD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 00 11 02 91 11 00 11 03 91 58 20 00 01 00 00 5d 13 07 20 03 00 00 00 7e ?? 01 00 04 7b } 		$a_03_1 = {11 00 11 02 11 00 11 03 91 9c 20 01 00 00 00 7e ?? 01 00 04 7b ?? 00 00 04 39 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}