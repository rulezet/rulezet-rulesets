rule Trojan_BAT_Tedy_ATD_MTB_3{
	meta:
		description = "Trojan:BAT/Tedy.ATD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 04 11 04 13 05 11 05 13 06 16 13 07 2b 19 00 09 06 07 11 07 91 06 8e 69 5d 93 6f 6d 00 00 0a 26 00 11 07 17 d6 13 07 11 07 11 06 fe 02 16 fe 01 13 08 11 08 2d d8 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}